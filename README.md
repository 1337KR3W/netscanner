## netscanner v1.0.0-beta

<img width="619" height="232" alt="image" src="https://github.com/user-attachments/assets/cc851d58-14de-429c-aab7-eadb0dac7e1c" />


**netscanner** is a tool designed in Python which works for Linux, Windows and macOS, that scans your private network to detect hosts. It uses the module **scapy** and returns **IP** and **MAC** of connected hosts in our private network via **ARP** packets.

# Installing
Make sure you are inside the repository folder.
### Virtual environment
It is recommended to use a virtual environment, where 'name' is the name you want, without quotes.
```
python -m venv 'name'
```
Activate the virtual environment where 'name' is the name from the previous step.
```
source name/bin/activate
```
### Installing dependencies
Use the `pip install -r` command to install the dependencies of the "requirements.txt" document.
```
pip install -r requirements.txt
```
# Using netscanner
To run the script simply use `sudo` (make sure you are in a virtual environment):
```
sudo python netscanner.py
```
It will request an **IP range**, for example: *192.168.1.0/24*

![image](https://github.com/josrojrom1/netscanner/assets/32680720/3f4858b1-5c5c-41a5-b62b-f350ddd87a86)

The tool will mark **hosts** and **gateway** in the provided **IP range**.

Remember to use the `deactivate` command when you finish using the netscanner tool to exit virtual environment.

<br/>
<br/>

---

*by 1337KR3W - pepecodesdev@gmail.com*
