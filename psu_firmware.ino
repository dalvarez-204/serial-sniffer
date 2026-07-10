/*
  Pretend-PSU firmware for the CLOAK demo.

  Mirrors the exact protocol invented in mimic_psu_traffic.py, so real
  traffic from this sketch matches what was already faked for testing the
  discovery UI/codegen — this is meant to run standalone (flash it in place
  of the oscilloscope sketch when demoing the PSU side).

  Frame: [0x02 STX] [CMD] [VALUE] [XOR checksum] [0x03 ETX] — always 5 bytes.

  Host -> board: CMD_SET_VOLTAGE, VALUE = commanded voltage scaled 0-255 over
  a 0-30V range.
  Board -> host: CMD_READ_CURRENT, VALUE = a fake current reading scaled
  0-255 over a 0-5A range, streamed periodically. Nothing is actually wired
  up — the "current" is derived from the last commanded voltage via a
  pretend load resistance, with a little jitter so it doesn't look like a
  suspiciously perfect reading.
*/

#define STX 0x02
#define ETX 0x03
#define CMD_SET_VOLTAGE 0x01
#define CMD_READ_CURRENT 0x02

#define VOLTAGE_VREF 30.0   // 0-30V PSU output range
#define CURRENT_VREF 5.0    // 0-5A current reading range
#define FAKE_LOAD_OHMS 12.0 // pretend resistive load, purely for a believable current reading

float commanded_voltage = 0.0;
unsigned long last_send = 0;
const unsigned long SEND_PERIOD_MS = 200;

uint8_t xor_checksum(uint8_t cmd, uint8_t value) {
  return cmd ^ value;
}

void send_frame(uint8_t cmd, uint8_t value) {
  Serial.write(STX);
  Serial.write(cmd);
  Serial.write(value);
  Serial.write(xor_checksum(cmd, value));
  Serial.write(ETX);
}

uint8_t to_byte(float value, float vref) {
  long raw = lround((value * 255.0) / vref);
  if (raw < 0) raw = 0;
  if (raw > 255) raw = 255;
  return (uint8_t)raw;
}

float from_byte(uint8_t raw, float vref) {
  return (raw * vref) / 255.0;
}

void handle_command(uint8_t cmd, uint8_t value) {
  if (cmd == CMD_SET_VOLTAGE) {
    commanded_voltage = from_byte(value, VOLTAGE_VREF);
  }
  // CMD_READ_CURRENT only ever goes board -> host in this protocol, so
  // there's nothing to handle if it somehow arrived as an incoming command
}

// same shape as read_packet()'s state machine in the real oscilloscope
// sketch, just for a fixed 5-byte frame instead of a variable-length one
void read_incoming() {
  static uint8_t idx = 0;
  static enum { WAIT_STX, READ_CMD, READ_VALUE, READ_CHK, READ_ETX } state = WAIT_STX;
  static uint8_t cmd = 0, value = 0, chk = 0;

  while (Serial.available()) {
    uint8_t b = Serial.read();
    switch (state) {
      case WAIT_STX:
        if (b == STX) state = READ_CMD;
        break;
      case READ_CMD:
        cmd = b;
        state = READ_VALUE;
        break;
      case READ_VALUE:
        value = b;
        state = READ_CHK;
        break;
      case READ_CHK:
        chk = b;
        state = READ_ETX;
        break;
      case READ_ETX:
        if (b == ETX && chk == xor_checksum(cmd, value)) {
          handle_command(cmd, value);
        }
        state = WAIT_STX;
        break;
    }
  }
}

void setup() {
  Serial.begin(115200);
  delay(2000); // let the boot-stage noise flush out, same as the oscilloscope sketch
  randomSeed(analogRead(0));
}

void loop() {
  read_incoming();

  unsigned long now = millis();
  if (now - last_send >= SEND_PERIOD_MS) {
    last_send = now;
    float fake_current = commanded_voltage / FAKE_LOAD_OHMS;
    fake_current += (float)random(-20, 21) / 1000.0; // small jitter, not a perfectly clean reading
    if (fake_current < 0) fake_current = 0;
    if (fake_current > CURRENT_VREF) fake_current = CURRENT_VREF;
    send_frame(CMD_READ_CURRENT, to_byte(fake_current, CURRENT_VREF));
  }
}
