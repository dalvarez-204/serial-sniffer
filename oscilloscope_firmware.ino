#include <Arduino.h>
#include <tinycbor.h> // tinycbor :)

// not sure why but this does not want to connect!
// got it :)))

// seems like I need to connect directly right? I don't have 
// a fancy client script to do the work for me :(

// prepare pins for ADC response !:)
#define ADC_PIN_1  34
#define ADC_PIN_2 35
#define DAC_PIN 25
#define SAMPLES_PER_PACKET 32
#define SAMPLE_PERIOD_MS 10 // Connect can display 1 value per ms live, so use this

#define PKT_TYPE_ADC 0x01
#define SAMPLES 16


// start and stop bytes
#define START_BYTE 0x7E
#define END_BYTE 0x7F
#define MAX_LEN 256 // 256 bytes

// controls 

#define PKT_CMD 0x10
#define CMD_START 0x01
#define CMD_STOP 0x02
#define CMD_GEN 0x03 // my signal generation message
#define CMD_GEN_OFF 0x04
unsigned long last_send=0;
bool streaming=true;

// signal generation stuff
#define WAVE_SAMPLES 64 // 64 points generated for wave sample
uint8_t sine_wave[WAVE_SAMPLES];
unsigned long last_update=0;
unsigned int signal_gen_speed=10; // arbitrary units?
float signal_gen_pk = 127;
int signal_gen_offset = 0;
bool signal_gen_enabled = false;
int waveform_idx=0;




// preparing the actual ADC packet :))

void send_ADC_packet() {
  /*
  This prepares the actual data in the packet
  grabs 16 samples of data per message
  */
  uint8_t payload[2+SAMPLES*2];
  uint8_t buyload[2+SAMPLES*2];

  payload[0] = PKT_TYPE_ADC;
  payload[1] = 0; // channel for first probe
  buyload[0]=PKT_TYPE_ADC;
  buyload[1]=1; // channel for the second probe

 // payload: [ type ][ ch ][ s0_lo ][ s0_hi ] [ s1_lo ][ s1_hi ] ...

  for (int i =0; i<SAMPLES; i++){
    uint16_t v = analogRead(ADC_PIN_1);
    uint16_t u = analogRead(ADC_PIN_2);
    payload[2+ 2*i] = v & 0xFF;
    payload[2 + 2*i + 1] = v >> 8;
    buyload[2+ 2*i] = u & 0xFF;
    buyload[2 + 2*i + 1] = u >> 8;
  }
  send_packet(payload, sizeof(payload));
  send_packet(buyload, sizeof(buyload));
}


void generate_wave(){
  /* 
  the code to actually put the signal on the generator pin
  
  sine_wave just represents our precalculated wave; it is not necessarily a sine wave
  */

  if (!signal_gen_enabled) return;

  unsigned long now = millis();
  if (now-last_update >= signal_gen_speed) {
    // float mult = signal_gen_pk
    dacWrite(DAC_PIN, (signal_gen_pk/(float)255)*sine_wave[waveform_idx]+signal_gen_offset);
    waveform_idx = (waveform_idx+1) % WAVE_SAMPLES;
    last_update=now;
  }
}

void start_signal_gen(uint8_t wave, uint8_t freq, uint8_t amp, uint8_t offset) {
  /* 
  takes information from command and develops the wave we are looking for 
  */
  waveform_idx=0;

  switch (wave) {
    case 0: // sine
      generate_sine_wave(); // regenerate the wave!
      break;
    case 1: // square
      for (int i=0; i<WAVE_SAMPLES; i++){
        sine_wave[i] = (i<WAVE_SAMPLES/2)? 0:255;
      }
      break;
    case 2: // triangle
      for (int i =0; i<WAVE_SAMPLES/2; i++){
        sine_wave[i] = map(i, 0, WAVE_SAMPLES/2, 0, 255);
      }
      for (int i = WAVE_SAMPLES/2; i<WAVE_SAMPLES; i++){
        sine_wave[i] = map(i, WAVE_SAMPLES/2, WAVE_SAMPLES, 255, 0);
      }
      break;
  }
  signal_gen_speed = freq;
  signal_gen_pk = amp;
  signal_gen_offset = offset;
  signal_gen_enabled = true;
}

void generate_sine_wave() {
  /*
  fill DAC_PIN with sine - creates a default signal
  
  */
  for (int i=0; i<WAVE_SAMPLES; i++){
    sine_wave[i] = (uint8_t)(127+127*sin(2*PI*i/WAVE_SAMPLES));
  }
}

void handle_commands(uint8_t* payload, uint16_t len){
  /*
  handle the commands from python interface
  */
  if (len==0) return;

  uint8_t cmd = payload[0];

  if (cmd== CMD_START) {
    streaming=true;
  }
  else if (cmd==CMD_STOP) {
    streaming=false;
  }
 
   // now we have our fancy wave generator going ! :)
  else if (cmd==CMD_GEN && len>=3){
    uint8_t wave = payload[1];
    uint8_t freq = payload[2];
    uint8_t amp = payload[3];
    uint8_t offset = payload[4];
    signal_gen_enabled = true;
    start_signal_gen(wave, freq, amp, offset);
  }
  else if (cmd==CMD_GEN_OFF){
    signal_gen_enabled=false;
  }
}

void handle_streaming() {
  /*
  decides when to send next data packet
  */
  if (!streaming) return;

  unsigned long now = millis();
  if (now - last_send >= SAMPLE_PERIOD_MS) {
    last_send=now; // probablyu will have a problem if last send not defined
    send_ADC_packet();
  }
}

uint8_t checksum(uint8_t *data, uint16_t len) {
  uint8_t c = 0;
  for (uint16_t i=0; i<len; i++){
    c ^= data[i];
  }
  return c;
}
void send_packet(uint8_t *payload, uint16_t len) {
  /*
  puts the whole message together and writes it to serial
  */
  Serial.write(START_BYTE);
  Serial.write((uint8_t*)&len, 2);
  Serial.write(payload, len);
  Serial.write(checksum(payload, len));
  Serial.write(END_BYTE);
}

uint16_t read_packet(uint8_t* payload){
  // parse the payload and return the length, and fill up the payload
  // this read packet is missing some crucial functionality for a good system
  // does not handle broken messages gracefully, and does not communicate to the PC 
  // when it fails to read a command - this would be modified for a real-world application
  enum State {WAIT_START, READ_LEN, READ_PAYLOAD, READ_CHK, READ_END};
  static State state = WAIT_START;
  static uint16_t len = 0;
  static uint16_t idx = 0;
  static uint8_t chk = 0;

  while (Serial.available()){
    uint8_t b = Serial.read();

    switch(state){
      case WAIT_START:
        if (b== START_BYTE) {
          state = READ_LEN;
          idx = 0;
          len=0;
        }
        break;
      // now find the length of things!
      case READ_LEN:
        if (idx==0){
          len = b;
          idx++;
        } else{
          len |= (b<<8);
          if (len>MAX_LEN){
            state=WAIT_START; // must be invalid? retry
            return -2;
          }
          idx=0;
          chk=0;
          state=READ_PAYLOAD;
        }
        break;
      // read the actual data now!! :)
      case READ_PAYLOAD:
        payload[idx++] = b;
        chk^=b;
        if (idx>=len) {
          state=READ_CHK;
        }
        break;

      // now check if this stuff is actually good
      case READ_CHK:
        if (b!=chk) {
          state= WAIT_START; // nooooooo checksum failed
          return -2;
        }
        state=READ_END;
        break;

      case READ_END:
        if (b!= END_BYTE) {
          state=WAIT_START; // bad end byte, retry
          return -2;
        }
        state = WAIT_START; // complete!
        return len;
        break;
    }
  }
  return -1; // no full packet yet :(

}

void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  delay(2000); //wait for the noise to flush out from the boot stage
  analogReadResolution(12);
}

void loop() {
  // put your main code here, to run repeatedly:
  
  // check if we read any commands

  if (Serial.available()) {
    uint8_t payload[MAX_LEN];
    uint16_t len = read_packet(payload);
    handle_commands(payload, len);
  }
  // handle_commands();
  handle_streaming();
  generate_wave();
  // static uint16_t samples[SAMPLES_PER_PACKET];
  // static size_t idx=0;
  // static unsigned long last_sample=0; // keep track of last sample time

  // if (millis()-last_sample >= SAMPLE_PERIOD_MS){
  //   last_sample=millis();
  //   samples[idx++] = analogRead(ADC_PIN);
    
  //   // check if our packet is full
  //   if (idx>=SAMPLES_PER_PACKET){
  //     send_ADC_packet(samples, idx);
  //     idx=0;
  //   }
  // }
}

/// testing stuff below, ignore all dat homie


// // test the communication interface by sending a little "pong" in response to python ping
// void sendPong() {
//   uint8_t buffer[64];
//   CborEncoder encoder, map;
//   cbor_encoder_init(&encoder, buffer, sizeof(buffer), 0);

//   // create CBOR map with 1 key/value pair :)
//   cbor_encoder_create_map(&encoder, &map, 1);
//   cbor_encode_text_stringz(&map, "msg");
//   cbor_encode_text_stringz(&map, "pong");
//   cbor_encoder_close_container(&encoder, &map);

//   uint32_t payload_len = cbor_encoder_get_buffer_size(&encoder, buffer);

//   Serial.write((uint8_t*)&payload_len, sizeof(payload_len));
//   Serial.write(buffer, payload_len);


// }