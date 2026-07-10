/*
  Pretend-PSU firmware for the CLOAK demo.

  Mirrors the exact protocol invented in mimic_psu_traffic.py, so real
  traffic from this sketch matches what was already faked for testing the
  discovery UI/codegen — this is meant to run standalone (flash it in place
  of the oscilloscope sketch when demoing the PSU side).

  Frame: [0x02 STX] [CMD] [payload] [XOR checksum] [0x03 ETX]. Single-field
  commands (set_voltage, set_ocp, set_ovp) carry one 16-bit big-endian value
  (6 bytes total); the reading response carries two (voltage, current — 8
  bytes total). Scale is 1000 for everything (raw = round(value * 1000)) —
  a single byte would only give ~0.12V of resolution over a 0-30V range,
  nowhere near enough to represent a real reading like 30.185V; 16 bits at
  this scale gives exact millivolt/milliamp resolution.

  Host -> board: CMD_SET_VOLTAGE / CMD_SET_OCP / CMD_SET_OVP.
  Board -> host: CMD_READING (actual voltage, actual current), streamed
  periodically. Nothing is actually wired up — this models real constant-
  voltage/constant-current PSU behavior with a pretend load resistance:
  below the OCP limit the load draws whatever current it wants and voltage
  holds at the commanded setpoint (CV mode); once the load would draw more
  than OCP allows, current clamps at the limit and voltage sags below the
  setpoint instead (CC mode) — a little jitter is added so it doesn't look
  like a suspiciously perfect reading.
*/

#define STX 0x02
#define ETX 0x03
#define CMD_SET_VOLTAGE 0x01
#define CMD_READING 0x02
#define CMD_SET_OCP 0x03
#define CMD_SET_OVP 0x04

#define SCALE 1000.0        // raw = round(value * SCALE) for every field
#define MAX_CURRENT 5.0     // amps — sanity clamp on the fake current reading
#define FAKE_LOAD_OHMS 12.0 // pretend resistive load, purely for a believable CV/CC transition

float commanded_voltage = 0.0;
float ocp_limit = MAX_CURRENT; // amps; defaults to "no limit" until the host sets one
float ovp_limit = 65535.0 / SCALE; // volts; defaults to "no limit" until the host sets one
unsigned long last_send = 0;
const unsigned long SEND_PERIOD_MS = 200;

uint8_t xor_checksum(const uint8_t *data, uint8_t len) {
  uint8_t result = 0;
  for (uint8_t i = 0; i < len; i++) result ^= data[i];
  return result;
}

void send_frame(uint8_t cmd, const uint8_t *payload, uint8_t len) {
  uint8_t buf[8];
  buf[0] = cmd;
  for (uint8_t i = 0; i < len; i++) buf[1 + i] = payload[i];
  Serial.write(STX);
  Serial.write(buf, 1 + len);
  Serial.write(xor_checksum(buf, 1 + len));
  Serial.write(ETX);
}

void to_bytes16(float value, uint8_t *out) {
  long raw = lround(value * SCALE);
  if (raw < 0) raw = 0;
  if (raw > 65535) raw = 65535;
  out[0] = (uint8_t)((raw >> 8) & 0xFF);
  out[1] = (uint8_t)(raw & 0xFF);
}

float from_bytes16(uint8_t hi, uint8_t lo) {
  uint16_t raw = ((uint16_t)hi << 8) | lo;
  return raw / SCALE;
}

void handle_command(uint8_t cmd, float value) {
  if (cmd == CMD_SET_VOLTAGE) {
    commanded_voltage = value;
  } else if (cmd == CMD_SET_OCP) {
    ocp_limit = value;
  } else if (cmd == CMD_SET_OVP) {
    ovp_limit = value;
  }
  // CMD_READING only ever goes board -> host in this protocol, so there's
  // nothing to handle if it somehow arrived as an incoming command
}

// same shape as read_packet()'s state machine in the real oscilloscope
// sketch, just for a fixed 6-byte incoming frame (single 16-bit-value
// commands are the only thing the host ever sends) instead of a
// variable-length one
void read_incoming() {
  static enum { WAIT_STX, READ_CMD, READ_HI, READ_LO, READ_CHK, READ_ETX } state = WAIT_STX;
  static uint8_t cmd = 0, hi = 0, lo = 0, chk = 0;

  while (Serial.available()) {
    uint8_t b = Serial.read();
    switch (state) {
      case WAIT_STX:
        if (b == STX) state = READ_CMD;
        break;
      case READ_CMD:
        cmd = b;
        state = READ_HI;
        break;
      case READ_HI:
        hi = b;
        state = READ_LO;
        break;
      case READ_LO:
        lo = b;
        state = READ_CHK;
        break;
      case READ_CHK:
        chk = b;
        state = READ_ETX;
        break;
      case READ_ETX: {
        uint8_t frame[3] = { cmd, hi, lo };
        if (b == ETX && chk == xor_checksum(frame, 3)) {
          handle_command(cmd, from_bytes16(hi, lo));
        }
        state = WAIT_STX;
        break;
      }
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

    float target_voltage = min(commanded_voltage, ovp_limit);
    float natural_current = target_voltage / FAKE_LOAD_OHMS;

    float actual_voltage, actual_current;
    if (natural_current > ocp_limit) {
      actual_current = ocp_limit;               // constant-current mode
      actual_voltage = actual_current * FAKE_LOAD_OHMS; // voltage sags below setpoint
    } else {
      actual_current = natural_current;          // constant-voltage mode
      actual_voltage = target_voltage;
    }
    actual_current += (float)random(-20, 21) / 1000.0; // small jitter, not a perfectly clean reading
    if (actual_current < 0) actual_current = 0;
    if (actual_current > MAX_CURRENT) actual_current = MAX_CURRENT;

    uint8_t payload[4];
    to_bytes16(actual_voltage, payload);
    to_bytes16(actual_current, payload + 2);
    send_frame(CMD_READING, payload, 4);
  }
}
