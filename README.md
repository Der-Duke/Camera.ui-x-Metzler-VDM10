# Camera.ui-x-Metzler-VDM10

The script is a small support for the Metzler VDM10 doorbells in combination with camera.ui for homebridge (thanks to seydx for his great work!).

The script is checking the traffic on the multicast ip and looks for a specific combination that is created by the VDM10 doorbell from Metzler.
In this case the event for ringing the bell.
If the doorbell event is recognized, an http event will trigger the http event of camera.ui will be triggerd.

Things you should know:
- run this script as a venv
- install the requirements
- in the script you muss add: source IP, destination IP, http event and adjustment on the multicast IP
- create a autostart service
