// Copyright (c) Microsoft Corporation. All rights reserved.
// SPDX-License-Identifier: MIT

/*
 * This is an Arduino-based Azure IoT Hub sample for ESPRESSIF ESP8266 board.
 * It uses our Azure Embedded SDK for C to help interact with Azure IoT.
 * For reference, please visit https://github.com/azure/azure-sdk-for-c.
 * 
 * To connect and work with Azure IoT Hub you need an MQTT client, connecting, subscribing
 * and publishing to specific topics to use the messaging features of the hub.
 * Our azure-sdk-for-c is an MQTT client support library, helping to compose and parse the
 * MQTT topic names and messages exchanged with the Azure IoT Hub.
 *
 * This sample performs the following tasks:
 * - Synchronize the device clock with a NTP server;
 * - Initialize our "az_iot_hub_client" (struct for data, part of our azure-sdk-for-c);
 * - Initialize the MQTT client (here we use Nick Oleary's PubSubClient, which also handle the tcp connection and TLS);
 * - Connect the MQTT client (using server-certificate validation, SAS-tokens for client authentication);
 * - Periodically send telemetry data to the Azure IoT Hub.
 * 
 * To properly connect to your Azure IoT Hub, please fill the information in the `iot_configs.h` file. 
 */

// C99 libraries
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <cstdlib>
#include <ArduinoJson.h>

// Libraries for MQTT client, WiFi connection and SAS-token generation.
#include <ESP8266WiFi.h>
#include <PubSubClient.h>
#include <WiFiClientSecure.h>
#include <base64.h>
#include <bearssl/bearssl.h>
#include <bearssl/bearssl_hmac.h>
#include <libb64/cdecode.h>

// Azure IoT SDK for C includes
#include <az_core.h>
#include <az_iot.h>
#include <azure_ca.h>

// Additional sample headers 
#include "iot_configs.h"

// When developing for your own Arduino-based platform,
// please follow the format '(ard;<platform>)'. 
#define AZURE_SDK_CLIENT_USER_AGENT "c%2F" AZ_SDK_VERSION_STRING "(ard;esp8266)"

// Utility macros and defines
#define BUZZ_PIN 5
#define RGB_RED 10
#define RGB_GREEN 9
#define RGB_BLUE 0
#define sizeofarray(a) (sizeof(a) / sizeof(a[0]))
#define ONE_HOUR_IN_SECS 3600
#define NTP_SERVERS "pool.ntp.org", "time.nist.gov"
#define MQTT_PACKET_SIZE 1024

// RFID pins and libraries
#include <SPI.h>
#include <MFRC522.h>
#define SS_PIN 15
#define RST_PIN 16

MFRC522 rfid(SS_PIN, RST_PIN); // Instance of the class

// Translate iot_configs.h defines into variables used by the sample
static const char* ssid = IOT_CONFIG_WIFI_SSID;
static const char* password = IOT_CONFIG_WIFI_PASSWORD;
static const char* host = IOT_CONFIG_IOTHUB_FQDN;
static const char* device_id = IOT_CONFIG_DEVICE_ID;
static const char* device_key = IOT_CONFIG_DEVICE_KEY;
static const int port = 8883;

// Memory allocated for the sample's variables and structures.
static WiFiClientSecure wifi_client;
static X509List cert((const char*)ca_pem);
static PubSubClient mqtt_client(wifi_client);
static az_iot_hub_client client;
static char sas_token[200];
static uint8_t signature[512];
static unsigned char encrypted_signature[32];
static char base64_decoded_device_key[32];
static char telemetry_topic[128];

int tono = 494;
int keepalive = 5;


static void rgbRed(){
  digitalWrite(RGB_RED,255);
  digitalWrite(RGB_GREEN,0);
  digitalWrite(RGB_BLUE,0);
}

static void rgbBlue(){
  digitalWrite(RGB_RED,0);
  digitalWrite(RGB_GREEN,0);
  digitalWrite(RGB_BLUE,255);
}

static void rgbGreen(){
  digitalWrite(RGB_RED,0);
  digitalWrite(RGB_GREEN,255);
  digitalWrite(RGB_BLUE,0);
}

static void rgbYellow(){
  digitalWrite(RGB_RED,255);
  digitalWrite(RGB_GREEN,255);
  digitalWrite(RGB_BLUE,0);
}

static void rgbOff(){
  digitalWrite(RGB_RED,0);
  digitalWrite(RGB_GREEN,0);
  digitalWrite(RGB_BLUE,0);
}

// Auxiliary functions

static void connectToWiFi()
{
  Serial.begin(115200);
  Serial.println();
  Serial.print("Connecting to WIFI SSID ");
  Serial.println(ssid);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED)
  {
    delay(500);
    Serial.print(".");
    rgbRed();
  }

  Serial.print("WiFi connected, IP address: ");
  Serial.println(WiFi.localIP());
  WiFi.setAutoReconnect(true);
  WiFi.persistent(true);
}

static void initializeTime()
{
  Serial.print("Setting time using SNTP");

  configTime(-6 * 3600, 0, NTP_SERVERS);
  time_t now = time(NULL);
  while (now < 1510592825)
  {
    delay(500);
    Serial.print(".");
    now = time(NULL);
  }
  Serial.println("done!");
}

static char* getCurrentLocalTimeString()
{
  time_t now = time(NULL);
  return ctime(&now);
}

static void printCurrentTime()
{
  Serial.print("Current time: ");
  Serial.print(getCurrentLocalTimeString());
}

void receivedCallback(char* topic, byte* payload, unsigned int length)
{
  Serial.print("Received [");
  Serial.print(topic);
  Serial.print("]: ");
  for (int i = 0; i < length; i++)
  {
    Serial.print((char)payload[i]);
  }
  Serial.println("");
}

static void initializeClients()
{
  az_iot_hub_client_options options = az_iot_hub_client_options_default();
  options.user_agent = AZ_SPAN_FROM_STR(AZURE_SDK_CLIENT_USER_AGENT);

  wifi_client.setTrustAnchors(&cert);
  if (az_result_failed(az_iot_hub_client_init(
          &client,
          az_span_create((uint8_t*)host, strlen(host)),
          az_span_create((uint8_t*)device_id, strlen(device_id)),
          &options)))
  {
    Serial.println("Failed initializing Azure IoT Hub client");
    return;
  }

  mqtt_client.setServer(host, port);
  mqtt_client.setCallback(receivedCallback);
  mqtt_client.setKeepAlive(keepalive);
}

/*
 * @brief           Gets the number of seconds since UNIX epoch until now.
 * @return uint32_t Number of seconds.
 */
static uint32_t getSecondsSinceEpoch()
{
  return (uint32_t)time(NULL);
}

static int generateSasToken(char* sas_token, size_t size)
{
  az_span signature_span = az_span_create((uint8_t*)signature, sizeofarray(signature));
  az_span out_signature_span;
  az_span encrypted_signature_span
      = az_span_create((uint8_t*)encrypted_signature, sizeofarray(encrypted_signature));

  uint32_t expiration = getSecondsSinceEpoch() + ONE_HOUR_IN_SECS;

  // Get signature
  if (az_result_failed(az_iot_hub_client_sas_get_signature(
          &client, expiration, signature_span, &out_signature_span)))
  {
    Serial.println("Failed getting SAS signature");
    return 1;
  }

  // Base64-decode device key
  int base64_decoded_device_key_length
      = base64_decode_chars(device_key, strlen(device_key), base64_decoded_device_key);

  if (base64_decoded_device_key_length == 0)
  {
    Serial.println("Failed base64 decoding device key");
    return 1;
  }

  // SHA-256 encrypt
  br_hmac_key_context kc;
  br_hmac_key_init(
      &kc, &br_sha256_vtable, base64_decoded_device_key, base64_decoded_device_key_length);

  br_hmac_context hmac_ctx;
  br_hmac_init(&hmac_ctx, &kc, 32);
  br_hmac_update(&hmac_ctx, az_span_ptr(out_signature_span), az_span_size(out_signature_span));
  br_hmac_out(&hmac_ctx, encrypted_signature);

  // Base64 encode encrypted signature
  String b64enc_hmacsha256_signature = base64::encode(encrypted_signature, br_hmac_size(&hmac_ctx));

  az_span b64enc_hmacsha256_signature_span = az_span_create(
      (uint8_t*)b64enc_hmacsha256_signature.c_str(), b64enc_hmacsha256_signature.length());

  // URl-encode base64 encoded encrypted signature
  if (az_result_failed(az_iot_hub_client_sas_get_password(
          &client,
          expiration,
          b64enc_hmacsha256_signature_span,
          AZ_SPAN_EMPTY,
          sas_token,
          size,
          NULL)))
  {
    Serial.println("Failed getting SAS token");
    return 1;
  }

  return 0;
}

static int connectToAzureIoTHub()
{
  size_t client_id_length;
  char mqtt_client_id[128];
  if (az_result_failed(az_iot_hub_client_get_client_id(
          &client, mqtt_client_id, sizeof(mqtt_client_id) - 1, &client_id_length)))
  {
    Serial.println("Failed getting client id");
    return 1;
  }

  mqtt_client_id[client_id_length] = '\0';

  char mqtt_username[128];
  // Get the MQTT user name used to connect to IoT Hub
  if (az_result_failed(az_iot_hub_client_get_user_name(
          &client, mqtt_username, sizeofarray(mqtt_username), NULL)))
  {
    printf("Failed to get MQTT clientId, return code\n");
    return 1;
  }

  Serial.print("Client ID: ");
  Serial.println(mqtt_client_id);

  Serial.print("Username: ");
  Serial.println(mqtt_username);

  mqtt_client.setBufferSize(MQTT_PACKET_SIZE);

  while (!mqtt_client.connected())
  {
    rgbYellow();
   
    time_t now = time(NULL);

    Serial.print("MQTT connecting ... ");

    if (mqtt_client.connect(mqtt_client_id, mqtt_username, sas_token))
    {
      Serial.println("connected.");
    }
    else
    {
      Serial.print("failed, status code =");
      Serial.print(mqtt_client.state());
      Serial.println(". Trying again in 1 second.");
      // Wait 1000 miliseconds before retrying
      rgbOff();
      delay(1000);
    }
  }

  mqtt_client.subscribe(AZ_IOT_HUB_CLIENT_C2D_SUBSCRIBE_TOPIC);

  return 0;
}

static void establishConnection() 
{
  connectToWiFi();
  initializeTime();
  printCurrentTime();
  initializeClients();
  
  // The SAS token is valid for 1 hour by default in this sample.
  // After one hour the sample must be restarted, or the client won't be able
  // to connect/stay connected to the Azure IoT Hub.
  if (generateSasToken(sas_token, sizeofarray(sas_token)) != 0)
  {
    Serial.println("Failed generating MQTT password");
  }
  else
  {
    connectToAzureIoTHub();
  }

  //digitalWrite(LED_PIN, LOW);
}

static String uidByteToString(){
  Serial.print("UID tag :");
  String content= "";
  for (byte i = 0; i < rfid.uid.size; i++) 
  {
     Serial.print(rfid.uid.uidByte[i] < 0x10 ? " 0" : " ");
     Serial.print(rfid.uid.uidByte[i], HEX);
     content.concat(String(rfid.uid.uidByte[i] < 0x10 ? " 0" : " "));
     content.concat(String(rfid.uid.uidByte[i], HEX));
  }
  Serial.println();
  content.toUpperCase();
  return content;
}

static String getTelemetryPayload()
{  
  String DeviceId = String(device_id);
  
  StaticJsonDocument<1024> doc;
  
  doc["DeviceId"] = DeviceId;
  doc["UID Tag"] = uidByteToString();
  doc["Date"] = getCurrentLocalTimeString();
  
  String Message;
  
  serializeJson(doc, Message);
  
  return Message;
}

static void sendTelemetry()
{
  //digitalWrite(LED_PIN, HIGH);
  Serial.print(millis());
  Serial.print(" ESP8266 Sending telemetry . . . ");
  if (az_result_failed(az_iot_hub_client_telemetry_get_publish_topic(
          &client, NULL, telemetry_topic, sizeof(telemetry_topic), NULL)))
  {
    Serial.println("Failed az_iot_hub_client_telemetry_get_publish_topic");
    return;
  }

  String Payload = getTelemetryPayload();

  Serial.print("Sending: ");
  Serial.println(Payload);
//  Serial.print("Into the next Topic: ");
//  Serial.println(telemetry_topic);
  mqtt_client.publish(telemetry_topic, (char*)Payload.c_str(), false);
  Serial.println("Sent OK");
  Serial.println();
  //delay(100);
  //digitalWrite(LED_PIN, LOW);
}

static void initializeRFID()
{
  //Serial.begin(115200);
  SPI.begin(); // Init SPI bus
  rfid.PCD_Init(); // Init MFRC522
  Serial.println();
  Serial.print(F("Reader :"));
  rfid.PCD_DumpVersionToSerial();
}

// Arduino setup and loop main functions.

void setup()
{   
  //pinMode(LED_PIN, OUTPUT);
  //pinMode(BUZZ_PIN, OUTPUT);
  pinMode(RGB_RED, OUTPUT);
  pinMode(RGB_GREEN, OUTPUT);
  pinMode(RGB_BLUE, OUTPUT);
  //digitalWrite(LED_PIN, HIGH);

//  analogWrite(BUZZ_PIN, 255);
//  delay(100);
//  analogWrite(BUZZ_PIN, 0);
//  delay(100);
//  analogWrite(BUZZ_PIN, 255);
//  delay(100);
//  analogWrite(BUZZ_PIN, 0);

  tone(BUZZ_PIN, tono);
  delay(100);
  noTone(BUZZ_PIN);
  delay(100);
  tone(BUZZ_PIN, tono);
  delay(100);
  noTone(BUZZ_PIN);
  
  establishConnection();
  initializeRFID();
}

void loop()
{   
  rgbGreen();

  // Reset the loop if no new card present on the sensor/reader. This saves the entire process when idle.
  if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
    // Show some details of the PICC (that is: the tag/card)
    Serial.print(F("PICC type: "));
    MFRC522::PICC_Type piccType = rfid.PICC_GetType(rfid.uid.sak);
    Serial.println(rfid.PICC_GetTypeName(piccType));

    // Halt PICC
    rfid.PICC_HaltA();
  
    // Stop encryption on PCD
    rfid.PCD_StopCrypto1();

    rgbBlue();

    if(!mqtt_client.connected())
    {
      establishConnection();
    }

    sendTelemetry();
    // MQTT loop must be called to process Device-to-Cloud and Cloud-to-Device.
    mqtt_client.loop();
    
    tone(BUZZ_PIN, tono);
    delay(100);
    noTone(BUZZ_PIN);
    delay(100);

    /*
    analogWrite(BUZZ_PIN, 255);
    delay(100);
    analogWrite(BUZZ_PIN, 0);
    delay(100);
    */
  }
  else {
    delay(500);
    mqtt_client.loop();
    return;
  }
  
  tone(BUZZ_PIN, tono);
  delay(100);
  noTone(BUZZ_PIN);
  delay(100);
  tone(BUZZ_PIN, tono);
  delay(100);
  noTone(BUZZ_PIN);

  /*
  analogWrite(BUZZ_PIN, 255);
  delay(100);
  analogWrite(BUZZ_PIN, 0);
  delay(100);
  analogWrite(BUZZ_PIN, 255);
  delay(100);
  analogWrite(BUZZ_PIN, 0);
   */
  
}
