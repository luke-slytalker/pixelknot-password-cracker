# Really janky PixelKnot password cracker I tossed together to help out.
# PROBLEM ---	since PixelKnot uses the last 1/3rd of the password to encrypt, we only try the LAST 3rd..
#		However... this is a slight problem in the case of:  abc123 & 1723
#		both of these will result in the cracker trying "23" as the password.
#		so, you may need to do some error mitigation after finding a possible password.
# Happy Hunting!

import os, sys, subprocess, math, argparse, datetime


parser = argparse.ArgumentParser(description='Script to check passwords against an image file.')

# Adding arguments for input image and passwords file
parser.add_argument('-i', '--image', type=str, help='Input image file', required=True)
parser.add_argument('-p', '--passwords', type=str, help='Passwords file', required=True)

# Adding a flag for checking for PixeKnot before starting the cracker.
parser.add_argument('-c', '--check', action='store_true', help='Performs a check on the image for indicators of PixelKnot')

args = parser.parse_args()

# Accessing the provided arguments
img = args.image
passwords_file = args.passwords
pk_check = args.check

# let's do it!
print("")
print("     PixelKnot Password Cracker   / @_Luke_Slytalker")
print("     ***********************************************")
print("")


def check_for_pixelknot(imgfile):

	####### PIXELKNOT CHECK PRIOR TO TRYING TO BRUTE FORCE #######
	print("    *****  CHECKING FOR PIXELKNOT  [ ENABLED ]  *****")
	
	with open(imgfile, 'rb') as f:
		# read in file
		s = f.read()
	
	pkscan = ""
	# find(byte-string, start, end)
	head1 = s.find(b'\xff\xd8\xff')  # regular header

	string1a = s.find(b'\x46\x49\x46\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb')
	string2a = s.find(b'\x03\x02\x02\x03\x02\x02\x03\x03\x03\x03\x04\x03\x03\x04\x05\x08\x05\x05\x04\x04\x05\x0a\x07\x07\x06\x08\x0c\x0a\x0c\x0c\x0b\x0a\x0b\x0b\x0d\x0e\x12\x10\x0d\x0e\x11\x0e\x0b\x0b\x10\x16\x10\x11\x13\x14\x15\x15\x15\x0c\x0f\x17\x18\x16\x14\x18\x12\x14\x15\x14')
	string2b = s.find(b'\x04\x03\x03\x04\x03\x03\x04\x04\x03\x04\x05\x04\x04\x05\x06\x0a\x07\x06\x06\x06\x06\x0d\x09\x0a\x08\x0a\x0f\x0d\x10\x10\x0f\x0d\x0f\x0e\x11\x13\x18\x14\x11\x12\x17\x12\x0e\x0f\x15\x1c\x15\x17\x19\x19\x1b\x1b\x1b\x10\x14\x1d\x1f\x1d\x1a\x1f\x18\x1a\x1b\x1a')
	string2c = s.find(b'\x49\x49\x2a\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xec\x00\x11\x44\x75\x63\x6b\x79\x00\x01\x00\x04\x00\x00\x00\x3c\x00\x00\xff\xee\x00\x0e\x41\x64\x6f\x62\x65\x00\x64\xc0\x00\x00\x00\x01\xff\xdb\x00\x84\x00\x06\x04\x04\x04\x05\x04\x06\x05')
	string3 = s.find(b'\x05\x04\x05\x09\x05\x05\x09\x14\x0d\x0b\x0d\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14\x14')
	found = s.find(b'\xFF\xC0\x00\x11\x08')
	last10 = s.find(b'\x03\x01\x22\x00\x02\x11\x01\x03\x11\x01')
	last5a = s.find(b'\xff\xda\x00\x0c\x03')
	last5b = s.find(b'\x8a\x29\x8c\x28\xa2')
	last5c = s.find(b'\xfe\xe5\x58\x8e\x3f')
	last5d = s.find(b'\x09\xe1\x85\x52\xcd')

	if head1 == 0:
		# found header
		if string2a != -1 or string2b != -1 or string2c != -1 or string1a != -1:
			# found next string
			if found != -1:
				# FOUND PK STRING
				if last10 != -1:
					# found the 10 byte string
					if last5a != -1 or last5b != -1 or last5c != -1 or last5d != -1:
						# pretty spot on that its a PixelKnot file
						pkscan = "FOUND"
					else:
						pkscan = "Not Found"
				else:
					pkscan = "Not Found"
			else:
				pkscan = "Not Found"
		else:
			pkscan = "Not Found"
	else:
		pkscan = "Not Found"
	
	return pkscan


def start_cracking(pwlist, img):

	# start the password cracking...
	print("\n")
	print("     CRACKING STARTED...")
	print("    ----Time: " + str(datetime.datetime.now()))
	print(f"    ----Image file: {img}")
	print(f"    ----Passwords file: {passwords_file}")
	print(f"    ----PixelKnot Check: {pk_check}")
	print("\n\n")

	with open(pwlist) as pw:	# open the file
		pword = pw.readline().strip()	# read a line in
		cnt = 1			# set our COUNTER to the 1st position

		while pword:	
			# while we have a password to try, we keep trying.
			# grab the last 1/3rd of the password
			passlen = len(pword) / 3
			last_third = math.ceil(passlen)
			negthird = -1 * last_third
			passw = pword[negthird:].strip()

			# build our command as an array of values
			comm = [ 'java', '--add-opens', 'java.base/sun.security.provider=ALL-UNNAMED', '-jar', 'f5.jar', 'x', '-p', passw, img ]

			# output the progress to our user
			print("Try # {}: Password:  {} \n   Last 1/3: {}".format(cnt, pword.strip(), passw))	

			# run our command and pipe the output back to a variable we'll call RESULT
			result = subprocess.Popen( comm, stdout=subprocess.PIPE ).communicate()[0]
			
			if str(result).find("only") > 0:
				#print("wrong password.")
				pword = pw.readline().strip()		# set the next line
				cnt += 1							# increase the counter

			else:
				# holy crap, we found something!!
				
				#if not os.path.exists("output.txt"):
				#	with open("output.txt", "w") as out:
				#		out.write("")
						
				with open('output.txt', 'r') as f:
					file_check = f.read()

				print("")
				print("------- !!!FOUND PASSWORD!!! -------")
				print("")
				print("Password:    [  " + str(pword) + "  ]")
				print("Try # " + str(cnt))
				print("Completed at " + str(datetime.datetime.now()))
				print(str(file_check))
				print("")
				pword = ""		# clear this variable and break out of our loop.


	print("------- CRACKING COMPLETE -------")


if pk_check:
	r = check_for_pixelknot(img)
	if r == "FOUND":
		# indicators found
		print("    ----PixelKnot indicators FOUND!")
		print("    ----Cracking commencing..")
		start_cracking(passwords_file, img)
	else:
		# no indicators found.. prompt for yes/no
		x = input("    ----PixelKnot indicators were not found.\n    ----Would you like to crack anyway?    Y or N:  ")
		if x != "Y" and x != "y":
			# they said no
			print("    Goodbye!")
			exit()
		else:
			start_cracking(passwords_file, img)

else:
	start_cracking(passwords_file, img)
		
