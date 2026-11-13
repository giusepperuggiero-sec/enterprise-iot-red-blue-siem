#include <WiFi.h>
#include <WiFiUdp.h> // For UDP syslog transmission
#include "arduino_secrets.h"

// --- STATIC NETWORK CONFIGURATION ---
IPAddress local_IP(SECRET_LOCAL_IP);
IPAddress gateway(SECRET_GATEWAY);
IPAddress subnet(SECRET_SUBNET);
IPAddress primaryDNS(SECRET_DNS);

// --- WI-FI CREDENTIALS ---
const char ssid[] = SECRET_SSID;
const char pass[] = SECRET_PASS;

// --- WAZUH SIEM SYSLOG CONFIGURATION ---
WiFiUDP udp;
const char* wazuh_ip = SECRET_WAZUH_IP;
const int syslog_port = SECRET_SYSLOG_PORT;

// --- SENSOR PIN CONFIGURATION ---
#define PIRPIN 3       // Motion sensor (D3)
#define SOUNDPIN 4     // Sound sensor (D4)

WiFiServer server(80);

// --- HIDS & ALARM STATE VARIABLES ---
unsigned long lastCheck = 0;
int reqCount = 0;
bool underAttack = false;
const int DOS_THRESHOLD = 3;

// HTTP parser safeguards against Slowloris / oversized header DoS
const size_t MAX_HTTP_HEADER_LEN = 512;
const unsigned long HTTP_CLIENT_TIMEOUT_MS = 2000UL;

// Acoustic alert cooldown so the latch auto-resets even without dashboard refreshes
const unsigned long SOUND_COOLDOWN_MS = 5000UL;
unsigned long lastSoundAlertMs = 0;
bool soundDetected = false;
int lastMotionState = LOW;

// Web dashboard active/standby toggle flag
bool dashboardActive = true;

// --- SEND SYSLOG MESSAGE TO WAZUH ---
void sendSyslog(const String& severity, const String& message) {
  String prival = "<13>";
  if (severity == "ALERT") prival = "<9>";
  if (severity == "ERROR") prival = "<11>";
  if (severity == "INFO") prival = "<14>";

  // Syslog program tag identifying the monitored node in Wazuh
  String syslogMsg;
  syslogMsg.reserve(prival.length() + 13 + message.length());
  syslogMsg = prival + "portenta_h7: " + message;

  udp.beginPacket(wazuh_ip, syslog_port);
  udp.print(syslogMsg);
  udp.endPacket();
}

void setup() {
  Serial.begin(115200);

  pinMode(LEDR, OUTPUT); pinMode(LEDG, OUTPUT); pinMode(LEDB, OUTPUT);
  digitalWrite(LEDR, HIGH); digitalWrite(LEDG, HIGH); digitalWrite(LEDB, HIGH);

  // Initialize sensor input pins
  pinMode(PIRPIN, INPUT);
  pinMode(SOUNDPIN, INPUT);

  delay(2000);
  Serial.println("Starting Security Terminal (PIR + Acoustic)...");

  // Apply the required static IP configuration
  WiFi.config(local_IP, gateway, subnet, primaryDNS);
  WiFi.setHostname("portenta_h7");

  Serial.println("Initializing Wi-Fi network...");

  while (WiFi.begin(ssid, pass) != WL_CONNECTED) {
    delay(500); Serial.print(".");
    digitalWrite(LEDB, LOW); delay(50); digitalWrite(LEDB, HIGH);
  }

  Serial.println("\n=== ONLINE ===");
  Serial.print("Assigned IP: "); Serial.println(WiFi.localIP());

  // Print hardware MAC address to serial console
  byte mac[6];
  WiFi.macAddress(mac);
  Serial.print("MAC Address (Hardware Lock): ");
  for (int i = 0; i < 6; ++i) {
    Serial.print(String(mac[i], HEX));
    if (i < 5) Serial.print(":");
  }
  Serial.println();

  digitalWrite(LEDG, LOW); delay(2000); digitalWrite(LEDG, HIGH);

  udp.begin(2390);
  server.begin();

  // Send initial startup log to Wazuh
  sendSyslog("INFO", "IoT device booted and connected to network.");
}

void loop() {
  const unsigned long now = millis();

  // --- CONTINUOUS MICROPHONE MONITORING (with non-blocking auto-reset cooldown) ---
  const int soundState = digitalRead(SOUNDPIN);
  if (soundState == HIGH && !soundDetected) {
    soundDetected = true;
    lastSoundAlertMs = now;
    sendSyslog("ALERT", "Alert! Suspicious noise detected in Server Room!");
  } else if (soundDetected && soundState == LOW && (now - lastSoundAlertMs >= SOUND_COOLDOWN_MS)) {
    // Re-arm acoustic trigger automatically even if no browser reloads the dashboard
    soundDetected = false;
  }

  // --- CONTINUOUS MOTION MONITORING ---
  int motionState = digitalRead(PIRPIN);
  if (motionState == HIGH && lastMotionState == LOW) {
    sendSyslog("ALERT", "Intrusion detected! Volumetric PIR sensor triggered.");
  }
  lastMotionState = motionState;

  // --- HIDS RATE MONITORING (Every 1 second) ---
  if (now - lastCheck >= 1000UL) {
    lastCheck = now;
    if (underAttack && reqCount == 0) {
      digitalWrite(LEDR, HIGH);
    }
    reqCount = 0;
    underAttack = false;
  }

  // --- WEB SERVER & DASHBOARD HANDLING ---
  WiFiClient client = server.available();
  if (client) {
    reqCount++;
    if (reqCount > DOS_THRESHOLD) {
      if (!underAttack) {
        underAttack = true;
        digitalWrite(LEDB, HIGH); digitalWrite(LEDR, LOW);
        sendSyslog("ERROR", "Possible DoS attack in progress! HTTP request threshold exceeded.");
      }
    }

    if (!underAttack) digitalWrite(LEDB, LOW);

    String header;
    header.reserve(256);
    boolean currentLineIsBlank = true;
    boolean headerTooLarge = false;
    const unsigned long reqStart = millis();

    while (client.connected() && (millis() - reqStart < HTTP_CLIENT_TIMEOUT_MS)) {
      if (client.available()) {
        char c = client.read();

        if (header.length() < MAX_HTTP_HEADER_LEN) {
          header += c;
        } else {
          headerTooLarge = true;
          break;
        }

        if (c == '\n' && currentLineIsBlank) {
          // --- DASHBOARD BUTTON HANDLERS ---
          if (header.indexOf("GET /off") >= 0 && dashboardActive) {
            dashboardActive = false;
            sendSyslog("ALERT", "Web Dashboard was manually DISABLED!");
          } else if (header.indexOf("GET /on") >= 0 && !dashboardActive) {
            dashboardActive = true;
            sendSyslog("INFO", "Web Dashboard was manually RE-ENABLED!");
          }

          // --- HTTP SERVER RESPONSES ---
          if (underAttack) {
            client.println("HTTP/1.1 503 Service Unavailable\r\nServer: Portenta-H7-Monitor\r\nContent-Type: text/html\r\nConnection: close\r\n");
            client.println("<html><body style='background-color: #c62828; color: white; text-align: center; font-family: Arial;'>");
            client.println("<h1 style='font-size: 50px; margin-top: 15%;'>[ ERROR 503 ]</h1>");
            client.println("<h2>Request rate limit exceeded!</h2><p>Service temporarily unavailable.</p></body></html>");

          } else if (!dashboardActive) {
            client.println("HTTP/1.1 200 OK\r\nServer: Portenta-H7-Monitor\r\nContent-Type: text/html\r\nConnection: close\r\n");
            client.println("<html><body style='background-color: #000000; color: #ff0000; text-align: center; font-family: monospace; padding-top: 15%;'>");
            client.println("<h1>[!] ACCESS DENIED [!]</h1><p>The Security Dashboard has been taken offline.</p>");
            client.println("<br><br><a href='/on' style='text-decoration:none;'><button style='background-color:#3fb950; color:white; font-weight:bold; padding:15px 30px; border:none; border-radius:5px; cursor:pointer; font-size: 16px;'>RE-ENABLE DASHBOARD</button></a>");
            client.println("</body></html>");

          } else {
            client.println("HTTP/1.1 200 OK\r\nServer: Portenta-H7-Monitor\r\nContent-Type: text/html\r\nConnection: close\r\n");
            client.println("<html><head><meta http-equiv='refresh' content='2'><title>Security Dashboard</title></head>");
            client.println("<body style='font-family: monospace; background-color: #0d1117; color: #58a6ff; padding: 20px;'>");
            client.println("<h1 style='border-bottom: 1px solid #58a6ff; padding-bottom: 10px;'>SECURITY TERMINAL - SERVER ROOM</h1>");

            client.println("<div style='border: 1px solid #30363d; padding: 20px; background-color: #161b22;'>");
            client.println("<h2 style='color: #c9d1d9;'>INTRUSION DETECTION</h2>");

            if (motionState == HIGH) {
              client.println("<p style='font-size: 20px;'><b>[!] Volumetric Sensor:</b> <span style='background-color: #da3633; color: white; padding: 5px;'>INTRUSION DETECTED! (Motion)</span></p>");
            } else {
              client.println("<p style='font-size: 20px;'><b>[+] Volumetric Sensor:</b> <span style='color: #3fb950;'>Area Secure</span></p>");
            }

            if (soundDetected) {
              client.println("<p style='font-size: 20px;'><b>[!] Acoustic Sensor:</b> <span style='background-color: #da3633; color: white; padding: 5px;'>ALERT! SUSPICIOUS NOISE!</span></p>");
            } else {
              client.println("<p style='font-size: 20px;'><b>[+] Acoustic Sensor:</b> <span style='color: #3fb950;'>Quiet (Normal)</span></p>");
            }
            client.println("</div>");

            client.println("<div style='border: 1px solid #30363d; padding: 20px; background-color: #161b22; margin-top: 20px;'>");
            client.println("<h2 style='color: #c9d1d9;'>NETWORK TELEMETRY & HIDS</h2>");
            client.print("<p><b>Node Uptime:</b> "); client.print(millis() / 1000); client.println(" sec</p>");
            client.print("<p><b>Web Traffic (Req/Sec):</b> "); client.print(reqCount); client.println("</p>");
            client.print("<p><b>HIDS Status:</b> <span style='color: #3fb950;'>Active (Secure)</span></p>");

            client.println("<hr style='border-color: #30363d; margin-top:20px; margin-bottom:20px;'>");
            client.println("<a href='/off' style='text-decoration:none;'><button style='background-color:#da3633; color:white; font-weight:bold; padding:10px 20px; border:none; border-radius:5px; cursor:pointer;'>DISABLE DASHBOARD</button></a>");

            client.println("</div></body></html>");
          }
          break;
        }
        if (c == '\n') {
          currentLineIsBlank = true;
        } else if (c != '\r') {
          currentLineIsBlank = false;
        }
      }
    }

    if (headerTooLarge) {
      client.println("HTTP/1.1 413 Payload Too Large\r\nServer: Portenta-H7-Monitor\r\nConnection: close\r\n");
    }

    delay(1);
    client.stop();
    if (!underAttack) digitalWrite(LEDB, HIGH);
  }
}

