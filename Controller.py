import logging
import re
import subprocess
import glob, os
import paramiko as paramiko


if 'vboxmanage_path' not in locals():
    vboxmanage_path = 'vboxmanage'
if 'timeout' not in locals():
    timeout = 60


def vboxmanage(cmd, timeout=timeout):
    vboxmanage_path = 'vboxmanage'
    cmd = f'{vboxmanage_path} {cmd}'.split()
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout, text=True)
        return result.returncode, result.stdout, result.stderr
    except FileNotFoundError:
        print("path is incorrect")
        exit(1)


def vm_start(vm, ui='gui'):
    result = vboxmanage(f'list runningvms ')
    vms_list = re.findall(r'^"(\w+)"', result[1], flags=re.MULTILINE)
    if vm in vms_list:
        return 'Vm is already running'
    if ui == '0':
        ui = 'headless'
    elif ui == '1':
        ui = 'gui'
    ui = ui.lower()
    if ui not in ['gui', 'sdl', 'headless', 'separate']:
        ui = 'gui'
    result = vboxmanage(f'startvm {vm} --type {ui}')
    if result[0] == 0:
        print("vm has been started")
    else:
        print("error while starting vm")
    return result[0], result[1], result[2]

def vm_poweroff(vm):
    logging.info(f'PoweringOff VM "{vm}".')
    result = vboxmanage(f'list runningvms ')
    vms_list = re.findall(r'^"(\w+)"', result[1], flags=re.MULTILINE)
    if vm not in vms_list:
        return 'Vm is already off'
    res = vboxmanage(f'controlvm {vm} poweroff')
    return res

def vmStatus(vmName):
    result = vboxmanage(f'list runningvms ')
    vms_list = re.findall(r'^"(\w+)"', result[1], flags=re.MULTILINE)
    if vmName in vms_list:
        return "on"
    elif vmName not in vms_list:
        return "off"

def vmsStatus():
    result1 = vboxmanage(f'list runningvms ')
    result2  = vboxmanage(f'list vms')
    running_vms = re.findall(r'^"(\w+)"', result1[1], flags=re.MULTILINE)
    all_vms = re.findall(r'^"(\w+)"', result2[1], flags=re.MULTILINE)
    list = []
    for vm in all_vms:
        vm_details = dict()
        if vm in running_vms:
            vm_details["vmName"] = vm
            vm_details["status"] = "on"
        else:
            vm_details["vmName"] = vm
            vm_details["status"] = "off"
        list.append(vm_details)
    return list

def changeCpuRam(vmName, amountOfRam, cpuNum):
    vms = vboxmanage(f'list vms')
    all_vms = re.findall(r'^"(\w+)"', vms[1], flags=re.MULTILINE)
    if vmName in all_vms:
        vboxmanage(f'modifyvm {vmName} --memory {amountOfRam}')
        vboxmanage(f'modifyvm {vmName} --cpus {cpuNum}')
        return "cpu and ram changed"
    else:
        return "vm does not exist"


def cloneVM(sourceVm, destVm):
    vms = vboxmanage(f'list vms')
    all_vms = re.findall(r'^"(\w+)"', vms[1], flags=re.MULTILINE)
    if sourceVm in all_vms:
        vboxmanage(f'clonevm {sourceVm} --name {destVm} --register')
        return 'cloned'
    else:
        return "Source VM does not exist"

def deleteVM(vmName):
    vms = vboxmanage(f'list vms')
    all_vms = re.findall(r'^"(\w+)"', vms[1], flags=re.MULTILINE)
    if vmName in all_vms:
        vboxmanage(f'unregistervm --delete {vmName}')
        return 'deleted'
    else:
        return "vm does not exist"


def executeCommand(vmName, command):
    vms = vboxmanage(f'list vms')
    all_vms = re.findall(r'^"(\w+)"', vms[1], flags=re.MULTILINE)
    result = vboxmanage(f'list runningvms ')
    running_list = re.findall(r'^"(\w+)"', result[1], flags=re.MULTILINE)
    if vmName in all_vms:
        if vmName in running_list :
            ip_address = vboxmanage(f' guestproperty get {vmName} /VirtualBox/GuestInfo/Net/0/V4/IP')
            ip = ip_address[1].replace('Value: ', '')
            res = " ".join(ip.split())
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(res, 22, username='vm1', password='1234')
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
            output = ssh_stdout.readlines()
            error = ssh_stderr.readlines()
            if len(output) != 0:
                return output
            else:
                return error

        else:
            return 'start the vm first'

    else:
        return 'vm does not exist'


def uploadToVm(vmName, location, vmLocation):
    vms = vboxmanage(f'list vms')
    all_vms = re.findall(r'^"(\w+)"', vms[1], flags=re.MULTILINE)
    result = vboxmanage(f'list runningvms ')
    running_list = re.findall(r'^"(\w+)"', result[1], flags=re.MULTILINE)
    if vmName in all_vms:
        if vmName in running_list:
            vboxmanage(f' guestcontrol {vmName} copyto --target-directory {vmLocation} --username vm1 --password 1234 {location}')
            return 'ok'
        else:
            return 'start the vm first'

    else:
        return 'vm does not exist'


def transfer(sourceVm, sourceLocation, destVm, destLocation):
    vms = vboxmanage(f'list vms')
    all_vms = re.findall(r'^"(\w+)"', vms[1], flags=re.MULTILINE)
    result = vboxmanage(f'list runningvms ')
    running_list = re.findall(r'^"(\w+)"', result[1], flags=re.MULTILINE)
    if sourceVm in all_vms and destVm in all_vms:
        if sourceVm in running_list and destVm in running_list:
            subprocess.run(f'vboxmanage guestcontrol {sourceVm} copyfrom --target-directory "C:\\Users\\asus\\PycharmProjects\\VMM\\broker" --username vm1 --password 1234 {sourceLocation}', capture_output=True, timeout=timeout, text=True)
            fileName = glob.glob("C:\\Users\\asus\\PycharmProjects\\VMM\\broker\\*")
            subprocess.run(f'vboxmanage guestcontrol {destVm} copyto --target-directory {destLocation} --username vm1 --password 1234 {fileName[0]}', capture_output=True, timeout=timeout, text=True)
            # print(b)
            os.remove(fileName[0])
            return 'ok'
        elif sourceVm not in running_list:
            return 'start the source vm first'
        else:
            return 'start the dest vm first'

    elif sourceVm not in all_vms:
        return 'source vm does not exist'
    else:
        return 'destination vm does not exist'

