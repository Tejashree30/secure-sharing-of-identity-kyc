from django.shortcuts import render
from django.template import RequestContext
from django.contrib import messages
from django.http import HttpResponse
import datetime
import os
import json
from web3 import Web3, HTTPProvider
from django.core.files.storage import FileSystemStorage
import hashlib
import smtplib

global details, username

def readDetails(contract_type):
    global details
    details = ""
    print(contract_type+"======================")
    blockchain_address = 'http://127.0.0.1:9545' #Blokchain connection IP
    web3 = Web3(HTTPProvider(blockchain_address))
    web3.eth.defaultAccount = web3.eth.accounts[0]
    compiled_contract_path = 'KYCContract.json' #Blockchain KYC SmartContract calling code
    deployed_contract_address = '0x95b442D8e001C3f8fA559d26a9fEAE7Ca4dd1317' #hash address to access Shared Data contract
    with open(compiled_contract_path) as file:
        contract_json = json.load(file)  # load contract info as JSON
        contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions
    file.close()
    contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi) #now calling contract to access data
    if contract_type == 'signup':
        details = contract.functions.getSignup().call()
    if contract_type == 'kyc':
        details = contract.functions.getKYC().call()    
    print(details)    

def saveDataBlockChain(currentData, contract_type):
    global details
    global contract
    details = ""
    blockchain_address = 'http://127.0.0.1:9545'
    web3 = Web3(HTTPProvider(blockchain_address))
    web3.eth.defaultAccount = web3.eth.accounts[0]
    compiled_contract_path = 'KYCContract.json' #Blockchain contract file
    deployed_contract_address = '0x95b442D8e001C3f8fA559d26a9fEAE7Ca4dd1317' #contract address
    with open(compiled_contract_path) as file:
        contract_json = json.load(file)  # load contract info as JSON
        contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions
    file.close()
    contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi)
    readDetails(contract_type)
    if contract_type == 'signup':
        details+=currentData
        msg = contract.functions.setSignup(details).transact()
        tx_receipt = web3.eth.waitForTransactionReceipt(msg)
    if contract_type == 'kyc':
        details+=currentData
        msg = contract.functions.setKYC(details).transact()
        tx_receipt = web3.eth.waitForTransactionReceipt(msg)

def updateKYCBlockchain(data):
    blockchain_address = 'http://127.0.0.1:9545'
    web3 = Web3(HTTPProvider(blockchain_address))
    web3.eth.defaultAccount = web3.eth.accounts[0]
    compiled_contract_path = 'KYCContract.json' #Blockchain contract file
    deployed_contract_address = '0x95b442D8e001C3f8fA559d26a9fEAE7Ca4dd1317' #contract address
    with open(compiled_contract_path) as file:
        contract_json = json.load(file)  # load contract info as JSON
        contract_abi = contract_json['abi']  # fetch contract's abi - necessary to call its functions
    file.close()
    contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi)
    msg = contract.functions.setKYC(data).transact()
    tx_receipt = web3.eth.waitForTransactionReceipt(msg)

def getEmail(user):
    global details
    email = ""
    readDetails('signup')
    arr = details.split("\n")
    for i in range(len(arr)-1):
        array = arr[i].split("#")
        if array[1] == user:
            email = array[4]
            break
    print("Email "+email)    
    return email

def sendMails(email, message):
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as connection:
        email_address = 'kaleem202120@gmail.com'
        email_password = 'xyljzncebdxcubjq'
        connection.login(email_address, email_password)
        connection.sendmail(from_addr="kaleem202120@gmail.com", to_addrs=email, msg="Subject : KYC Access Notification\n\nYour KYC Access by "+message)


def AccessKYCAction(request):
    if request.method == 'POST':
        global username
        user = request.POST.get('t1', False)
        email = getEmail(user)
        sendMails(email, user)
        strdata = '<table border=1 align=center width=100%><tr><th><font size="" color="black">Username</th><th><font size="" color="black">Description</th>'
        strdata+='<th><font size="" color="black">Hashcode</th><th><font size="" color="black">Uploaded Date Time</th>'
        strdata+='<th><font size="" color="black">Identify Proof</th><th><font size="" color="black">Status</th></tr>'
        readDetails('kyc')
        arr = details.split("\n")
        for i in range(len(arr)-1):
            array = arr[i].split("#")
            if array[0] == user:
                strdata+='<tr><td><font size="" color="black">'+str(array[0])+'</td><td><font size="" color="black">'+array[1]+'</td><td><font size="" color="black">'+str(array[2])+'</td>'
                strdata+='<td><font size="" color="black">'+str(array[3])+'</td>'
                strdata+='<td><img src="static/files/'+array[4]+'" height="150" width="150"/></td>'
                strdata+='<td><font size="" color="black">'+str(array[5])+'</td></tr>'
        context= {'data':strdata}
        return render(request, 'AdminScreen.html', context)
        

def AccessKYC(request):
    if request.method == 'GET':
        users = '<tr><td><font size="3" color="black">Choose&nbsp;User</td><td><select name="t1">'
        readDetails('kyc')
        arr = details.split("\n")
        for i in range(len(arr)-1):
            array = arr[i].split("#")
            users += '<option value="'+array[0]+'">'+array[0]+'</option>'
        users += "</select></td></tr>"
        context= {'data1': users}
        return render(request, 'AccessKYC.html', context)         

def UpdateKYCAction(request):
    if request.method == 'GET':
        user = request.GET.get('t1', False)
        status = request.GET.get('t2', False)
        data = ""
        readDetails('kyc')
        arr = details.split("\n")
        for i in range(len(arr)-1):
            array = arr[i].split("#")
            if array[0] != user:
                data += arr[i]+"\n"
            else:
                data += array[0]+"#"+array[1]+"#"+array[2]+"#"+array[3]+"#"+array[4]+"#"+status+"\n"
        updateKYCBlockchain(data)
        context= {'data':user+" KYC Updated Successfully"}
        return render(request, 'AdminScreen.html', context)    

def ViewKYC(request):
    if request.method == 'GET':
        strdata = '<table border=1 align=center width=100%><tr><th><font size="" color="black">Username</th><th><font size="" color="black">Description</th>'
        strdata+='<th><font size="" color="black">Hashcode</th><th><font size="" color="black">Uploaded Date Time</th>'
        strdata+='<th><font size="" color="black">Identify Proof</th><th><font size="" color="black">Status</th><th><font size="" color="black">Accept KYC</th><th><font size="" color="black">Reject KYC</th></tr>'
        readDetails('kyc')
        arr = details.split("\n")
        for i in range(len(arr)-1):
            array = arr[i].split("#")
            if array[5] == 'Pending':
                strdata+='<tr><td><font size="" color="black">'+str(array[0])+'</td><td><font size="" color="black">'+array[1]+'</td><td><font size="" color="black">'+str(array[2])+'</td>'
                strdata+='<td><font size="" color="black">'+str(array[3])+'</td>'
                strdata+='<td><img src="static/files/'+array[4]+'" height="150" width="150"/></td>'
                strdata+='<td><font size="" color="black">'+str(array[5])+'</td>'
                strdata+='<td><a href=\'UpdateKYCAction?t1='+array[0]+'&t2=Accepted\'><font size=3 color=black>Accept KYC</font></a></td>'
                strdata+='<td><a href=\'UpdateKYCAction?t1='+array[0]+'&t2=Rejected\'><font size=3 color=black>Reject KYC</font></a></td></tr>'
        context= {'data':strdata}
        return render(request, 'AdminScreen.html', context)           

def checkKYC(user):
    global details
    flag = False
    readDetails('kyc')
    arr = details.split("\n")
    for i in range(len(arr)-1):
        array = arr[i].split("#")
        if array[0] == user:
            flag = True
            break
    return flag

def CheckStatus(request):
    if request.method == 'GET':
        global username
        strdata = '<table border=1 align=center width=100%><tr><th><font size="" color="black">Username</th><th><font size="" color="black">Description</th>'
        strdata+='<th><font size="" color="black">Hashcode</th><th><font size="" color="black">Uploaded Date Time</th>'
        strdata+='<th><font size="" color="black">Identify Proof</th><th><font size="" color="black">Status</th></tr>'
        readDetails('kyc')
        arr = details.split("\n")
        for i in range(len(arr)-1):
            array = arr[i].split("#")
            if array[0] == username:
                strdata+='<tr><td><font size="" color="black">'+str(array[0])+'</td><td><font size="" color="black">'+array[1]+'</td><td><font size="" color="black">'+str(array[2])+'</td>'
                strdata+='<td><font size="" color="black">'+str(array[3])+'</td>'
                strdata+='<td><img src="static/files/'+array[4]+'" height="150" width="150"/></td>'
                strdata+='<td><font size="" color="black">'+str(array[5])+'</td></tr>'
        context= {'data':strdata}
        return render(request, 'UserScreen.html', context)   

def UploadKYCAction(request):
    if request.method == 'POST':
        global username, hash_obj
        desc = request.POST.get('t1', False)
        filename = request.FILES['t2'].name
        myfile = request.FILES['t2'].read()
        kyc = checkKYC(username)
        output = "Your KYC already exists"
        if kyc == False:
            hash_object = hashlib.sha1(username.encode())
            hashcode = hash_object.hexdigest()
            with open("SecureApp/static/files/"+filename, "wb") as file:
                file.write(myfile)
            file.close()
            now = datetime.datetime.now()
            current_time = now.strftime("%Y-%m-%d %H:%M:%S")
            user = username
            data = user+"#"+desc+"#"+str(hashcode)+"#"+str(current_time)+"#"+filename+"#Pending\n"
            saveDataBlockChain(data,"kyc")
            output = 'Your KYC Securely Saved inside Blockchain with Hashcode : '+str(hashcode)
        context= {'data':output}
        return render(request, 'UploadKYC.html', context)        
    
def UploadKYC(request):
    if request.method == 'GET':
       return render(request, 'UploadKYC.html', {})

def index(request):
    if request.method == 'GET':
       return render(request, 'index.html', {})

def AdminLogin(request):
    if request.method == 'GET':
       return render(request, 'AdminLogin.html', {})

def UserLogin(request):
    if request.method == 'GET':
       return render(request, 'UserLogin.html', {})    

def Register(request):
    if request.method == 'GET':
       return render(request, 'Register.html', {})

def UserLoginAction(request):
    if request.method == 'POST':
        global username
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        readDetails('signup')
        arr = details.split("\n")
        status = "none"
        for i in range(len(arr)-1):
            array = arr[i].split("#")
            if array[1] == username and password == array[2] and array[6] == "User":
                status = "Welcome "+username
                break
        if status != 'none':
            context= {'data':status}
            return render(request, 'UserScreen.html', context)
        else:
            context= {'data':'login failed'}
            return render(request, 'UserLogin.html', context)

def AdminLoginAction(request):
    if request.method == 'POST':
        global username
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        readDetails('signup')
        arr = details.split("\n")
        status = "none"
        for i in range(len(arr)-1):
            array = arr[i].split("#")
            if array[1] == username and password == array[2] and array[6] == "BankAdmin":
                status = "Welcome "+username
                break
        if status != 'none':
            context= {'data':status}
            return render(request, 'AdminScreen.html', context)
        else:
            context= {'data':'login failed'}
            return render(request, 'AdminLogin.html', context)        

        
def RegisterAction(request):
    if request.method == 'POST':
        global details
        username = request.POST.get('t1', False)
        password = request.POST.get('t2', False)
        contact = request.POST.get('t3', False)
        email = request.POST.get('t4', False)
        address = request.POST.get('t5', False)
        usertype = request.POST.get('t6', False)
        output = "Username already exists"
        readDetails('signup')
        arr = details.split("\n")
        status = "none"
        for i in range(len(arr)-1):
            array = arr[i].split("#")
            if array[1] == username:
                status = username+" already exists"
                break
        if status == "none":
            details = ""
            data = "signup#"+username+"#"+password+"#"+contact+"#"+email+"#"+address+"#"+usertype+"\n"
            saveDataBlockChain(data,"signup")
            context = {"data":"Signup process completed and record saved in Blockchain"}
            return render(request, 'Register.html', context)
        else:
            context = {"data":status}
            return render(request, 'Register.html', context)









        


