import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import email
import base64 #add Base64
import re
import requests
import json
import getpass
import re
from pprint import pprint
from fortigate_api import FortigateAPI #requires fortigate-api 1.4.0
import time
current_time = time.time()
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
#lines to edit- necessary: 27,28,29,30, 231, optional:240

def start():
	global check_duration
	global HOST
	global PORT
	global VDOM
	global fgt
	check_duration = 5 #How often in seconds will the scanner check the canarylog for changes (default:5)
	HOST = "###.###.###.###" #IP address to access Fortigate firewall
	PORT = "###" #Management port for firewall
	VDOM = "######" #VDOM to manage

	while True:
		try:
			print("Please enter your Fortigate Username or q to quit")
			USERNAME = input()
			if USERNAME == "exit" or USERNAME == "q":
				exit()
			print("Please enter your password")
			PASSWORD = getpass.getpass()
			fgt = FortigateAPI(host=HOST, username=USERNAME, password=PASSWORD, port=PORT, vdom=VDOM)
			fgt.login()
			fgt.logout()
			break
		except ValueError:
			print("Invalid login credentials.")

def user_program():
	while True:
		print("""Please enter a selection:
		1. Run auto-blocking program.
		2. Quit""")
		selection = input()
		if selection == str("1"):
			fgt.login()
			response = fgt.address_group.is_exist(uid="PYTHONVPN_GROUP")
			if response == False:
				pythonvpn_group_creator()
			fgt.logout()
			timer_s=0
			timer_m=0
			timer_h=0
			timer_d=0
			print("Scanner running! Checking every " + str(check_duration) +" seconds.")
			while True:
				try:
					#email_log_check.main()
					main()
					print("\rCurrent runtime " + str(timer_d) + "d " + str(timer_h) + "h " + str(timer_m) + "m " + str(timer_s) + "s Press ctrl+c to stop." , end="")
					time.sleep(check_duration)
					timer_s += check_duration
					if timer_s == 60:
						timer_m += 1
						timer_s = 0
					if timer_m == 60:
						timer_h += 1
						timer_m = 0
					if timer_h == 24:
						timer_d += 1
						timer_h =0
				except KeyboardInterrupt:
					break
			fgt.logout()
		elif selection == str("2"):
			fgt.logout()
			exit()
		else:
			print("Invalid selection.")
			fgt.logout()
			break

def pythonvpn_group_creator():
	while True:
		print("\nPYTHONVPN_GROUP does not exist in firewall. We can create PYTHONVPN_GROUP for you now, but you must add PYTHONVPN_GROUP to your firewall blocking policies for this scanner to be effective.")
		print("\nIf you continue, address \"tttemporaryvpnaddress\" with ip 169.254.0.50 255.255.255.255 will be created as a placeholder for now, since Fortigate does not allow empty groups.\n\n Continue with creation?. Y/N \n")
		any_key = input()
		if any_key == "N" or any_key == "n":
			fgt.logout()
			print("Quitting!")
			raise SystemExit
		elif any_key == "Y" or any_key == "y":
			data = {"name": "tttemporaryvpnaddress",
				"obj-type": "ip",
				"subnet": "169.254.0.50 255.255.255.255",
				"type": "ipmask"}
			response = fgt.address.create(data=data)
			print("Created temporary address to add to PYTHONVPN_GROUP " + str(response))
			data = {"name": "PYTHONVPN_GROUP", "member": [{"name": "tttemporaryvpnaddress"}]}
			response = fgt.address_group.create(data=data)
			print("Added temporary address to PYTHONVPN_GROUP." + str(response))
			break

def main():
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

        #Filter and get the IDs of the message I need.
        #I'm just filtering messages that have the label "UNREAD"

    try:
        service = build('gmail', 'v1', credentials=creds)
        search_id = service.users().messages().list(userId='me', labelIds="UNREAD").execute() #looks for unread mail
        number_result = search_id['resultSizeEstimate']

        final_list = [] # empty array, all the messages ID will be listed here

        #mark unread as read
        search_id_2 = service.users().threads().list(userId='me', labelIds="UNREAD").execute()
        ids= search_id_2.get("threads", [])
        mark_as_read_data = {"removeLabelIds": "UNREAD"}
        for idx in ids:
            id_to_mark_read= (idx["id"])
            mark_as_read = service.users().threads().modify(userId='me', id=id_to_mark_read, body=mark_as_read_data).execute()
        ###/mark unread as read###

        if number_result>0:
            message_ids = search_id['messages']

            for ids in message_ids:
                final_list.append(ids['id'])
                # call the function that will call the body of the message
                get_message(service, ids['id'] )

            return final_list

        # If there are not messages with those criterias
        #The message 'There were 0 results for that search string' will be printed.

        else:
            #print('There were 0 results for that search string')
            return ""


    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An error occurred: {error}')


        #new function to get the body of the message, and decode the message

def get_message(service, msg_id):

    try:
        message_list=service.users().messages().get(userId='me', id=msg_id, format='raw').execute()

        msg_raw = base64.urlsafe_b64decode(message_list['raw'].encode('ASCII'))

        msg_str = email.message_from_bytes(msg_raw)

        content_types = msg_str.get_content_maintype()

        #since fortigate only sends plain text emails, we can bypass reading anything that is not plain text

        if content_types == 'multipart':
            pass
            #part1, part2 = msg_str.get_payload()
            #print("This is the message body, html:")
            #print(part1.get_payload())
            #return part1.get_payload()
        else:
            #print("This is the message body plain text:")
            #print(base64.b64decode(msg_str.get_payload()))
            search_message(base64.b64decode(msg_str.get_payload()))
            #return base64.b64decode(msg_str.get_payload())


    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An error occurred: {error}')

def search_message(message_data):
    #searches for email with ip address preceeded by "remip". These emails are sent from fortigate when a VPN user connects.
    #if no email is found, searches again for ip address preceeded by "srcip". These emails are sent from fortigate when an admin connects to the firewall admin portal.
    ip_full = re.search("remip=\d(\d)?(\d)?.\d(\d)?(\d)?.\d(\d)?(\d)?.\d(\d)?(\d)?", str(message_data))
    if ip_full == None:
        ip_full = re.search("srcip=\d(\d)?(\d)?.\d(\d)?(\d)?.\d(\d)?(\d)?.\d(\d)?(\d)?", str(message_data))
        print("\n\n---Administrator login detected.---")
        current_time = time.time()
        log_file = open("logfile.txt", "a")
        log_file.write("\nAdministrator login detected." + " " + time.strftime("%m-%d-%Y %I:%M %p %Z", time.localtime(current_time)))
        log_file.close()
    ip_only = re.search("\d(\d)?(\d)?.\d(\d)?(\d)?.\d(\d)?(\d)?.\d(\d)?(\d)?", ip_full.group())

    # Defining the api-endpoint
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': ip_only.group(),
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': '########'
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    # Formatted output
    decodedResponse = json.loads(response.text)
    #print(json.dumps(decodedResponse, sort_keys=True, indent=4))
    abuse_score=(decodedResponse["data"]["abuseConfidenceScore"])
    abuse_threshold = 1
    if abuse_score > abuse_threshold: # modify the abuse score to your liking. 
        ban_function(ip_only.group())
    else:
        current_time = time.time()
        print("\nNew IP " +str(ip_only.group()) + " connected, abuse score is less than " +str(abuse_threshold) + ". Not banning" + " " + time.strftime("%m-%d-%Y %I:%M %p %Z", time.localtime(current_time)))
        log_file = open("logfile.txt", "a")
        log_file.write("\nNew IP " +str(ip_only.group()) + " connected, abuse score is less than " + +str(abuse_threshold) + ". Not banning" + " " + time.strftime("%m-%d-%Y %I:%M %p %Z", time.localtime(current_time)))
        log_file.close()

############
def ban_function(ip_to_ban):
    print("\nAbusive IP found, banning: " + str(ip_to_ban))
    fgt.login()
    #get list of blocked IPs and assign it to a list - address_ip_list
    address1 = 1
    address_ip_list = []
    address_name_list = []
    while True:
        #loops through all the "pythonvpnaddress" addresses
        addresses = str(fgt.address.get(uid="pythonvpnaddress"+str(address1)))
        #print(str(addresses))
        if addresses == "[]":
            break
        addressname = re.search("pythonvpnaddress(\S)?", addresses)
        address_name_list.append(addressname.group())
        addressip = re.search("\d(\d)?(\d)?\.\d(\d)?(\d)?\.\d(\d)?(\d)?\.\d(\d)?(\d)?", addresses)
        address_ip_list.append(addressip.group())
        address1 += 1
    if ip_to_ban in address_ip_list:
        print("IP detected, but already in ban list. Be sure to add PYTHONVPN_GROUP to firewall ban rules!")
        current_time = time.time()
        log_file = open("logfile.txt", "a")
        log_file.write("\nIP detected, but already in ban list. Be sure to add PYTHONVPN_GROUP to firewall ban rules!" + str(ip_to_ban) + " " + time.strftime("%m-%d-%Y %I:%M %p %Z", time.localtime(current_time)))
        log_file.close()
    else:
        #clears PYTHONVPN_GROUP, neccessary in order to delete pythonaddresses
        data = {"name": "tttemporaryvpnaddress",
            "obj-type": "ip",
            "subnet": "169.254.0.50 255.255.255.255",
            "type": "ipmask"}
        response = fgt.address.create(data=data)
        #print("Created temporary address to add to PYTHONVPN_GROUP " + str(response))
        data = {"name": "PYTHONVPN_GROUP", "member": [{"name": "tttemporaryvpnaddress"}]}
        response = fgt.address_group.update(data=data)
        #print("Added temporary address to PYTHONVPN_GROUP, clearing other addresses " + str(response))
        #delete all addresses in PYTHONVPN_GROUP on fortigate, necessary so that they can be readded without conflicts
        for name in address_name_list:
            response = fgt.address.delete(filter="name=@"+str(name))
        #    print("Cleared address " + str(name) + " " + str(response))
        #creates all addresses to be added to PYTHONVPN_GROUP, including new address, necessary because single address cannot be added to group, all need to be readded each time
        address_ip_list.append(ip_to_ban)
        address2 = 1
        data_member = []
        for address in address_ip_list:
            data = {"name": "pythonvpnaddress" + str(address2),
            "obj-type": "ip",
            "subnet": str(address) + " 255.255.255.255",
            "type": "ipmask"}
            response = fgt.address.create(data=data)
            data_member.append({"name": "pythonvpnaddress"+str(address2)})
           # print("Rebuilding blocklist! Address " + str(address2)  + str(response))
            address2 += 1
        #write address_ip_list to PYTHONVPN_GROUP to block it
        data_group = {"name": "PYTHONVPN_GROUP", "member": ""}
        data_group["member"] = data_member
        response = fgt.address_group.update(data=data_group)
        #print("Blocklist rebuilt! PYTHONVPN_GROUP rebuilt ", response)
        response = fgt.address.delete(uid="tttemporaryvpnaddress")
        #print("Temporary address deleted! ", response)
        current_time = time.time()
        print("New IP blocked - " + str(ip_to_ban) + " " + time.strftime("%m-%d-%Y %I:%M %p %Z", time.localtime(current_time)))
        log_file = open("logfile.txt", "a")
        log_file.write("\nNew IP blocked - " + str(ip_to_ban) + " " + time.strftime("%m-%d-%Y %I:%M %p %Z", time.localtime(current_time)))
        log_file.close()
    fgt.logout
    #email_log.main()

### Start running here:
start()
user_program()

