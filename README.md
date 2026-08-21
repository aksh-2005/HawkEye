# HawkEye: App Privilege Analyzer

## Running on Local Network

To access HawkEye from another device (phone, tablet, or another computer) on the same Wi-Fi / local network:

1. Start the application:
   ```bash
   python app.py
   ```
2. When the server starts, check the terminal output for your local network IP (e.g. `http://192.168.x.x:5000`).
3. Enter `http://<YOUR_LOCAL_IP>:5000` in the browser on any device connected to the same network.

### Windows Firewall Troubleshooting
If other devices cannot connect:
- Ensure both devices are connected to the same network (Wi-Fi/Ethernet).
- Ensure your network profile on Windows is set to **Private**.
- Allow Port 5000 in Windows Firewall (Inbound Rule) or temporarily allow Python through the firewall when prompted.

