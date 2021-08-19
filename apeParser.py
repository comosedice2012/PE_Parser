#!/usr/bin/env python3

import pefile, struct, hashlib, argparse, math, os, sys, requests, vt, colorama
from colorama import Fore, Style

#---------------------------------------------------------------------------------
def get_args():
    """Get command line arguments"""

    parser = argparse.ArgumentParser(description='PE file parsing utility')
    parser.add_argument('file',
                        help="Readable PE file",
                        metavar='FILE'
                        )

    parser.add_argument('-s',
                        '--strings',
                        help='File to write strings to',
                        metavar='FILE',
                        default='peStrings.txt')

    args = parser.parse_args()
    
    #check if file exists and if it has "Magic" number
    if not os.path.isfile(args.file) or open(args.file, "rb").read(2).decode() != 'MZ':
        parser.error(f'"{args.file}" is not a valid PE file.')

    return args


#---------------------------------------------------------------------------------
def getHashes(args, impHash):
    """Get file hashes"""

    hash_md5 = hashlib.md5()
    hash_sha256 = hashlib.sha256()

    with open(args.file, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
            hash_sha256.update(chunk)

    print(f'\n[{Fore.GREEN}+{Style.RESET_ALL}] Hashes:')
    print(f'    SHA256:  {hash_sha256.hexdigest()}')
    print(f'    MD5:     {hash_md5.hexdigest()}')
    print(f'    imphash: {impHash}\n')
    
    return hash_md5


#---------------------------------------------------------------------------------
def getImports(pe):
    """Get file Libraries/Imports"""

    importTable = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        library = entry.dll.decode()
        functions = []
        for x in entry.imports:
            functions.append(x.name.decode())
        field = {library: functions}
        importTable.append(field)

    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Imports table:\n')
    for entry in importTable:
        for key, value in entry.items():
            for x in range(len(value)):
                print(f'    {key if x == 0 else "":30}{value[x]}')
    print(f'\n')


#---------------------------------------------------------------------------------
def getSections(pe):
    """Get section information"""

    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] {"Number of Sections: ":30s}{pe.FILE_HEADER.NumberOfSections} ')
    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Section table:\n')
    print(f'\n     {" Name":12}{"V_Size":11}{"V_Addr":12}{"Data Size":15}{"Entropy":13}{"Packed":}')
    print(f'    {"-"*70}')

    for section in pe.sections:
        entropy = section.get_entropy()
        packed = ''
        if entropy > 6:
            packed = 'Maybe'
        if entropy > 7:
            packed = 'Yes'
        name = section.Name.decode().replace("\x00", "")
        vSize = section.Misc_VirtualSize
        rawDataSize = section.SizeOfRawData
        vAddr = section.VirtualAddress

        print(f'     {name:7}{vSize:11}{vAddr:11}{rawDataSize:13}{entropy:12.03f}\t      {packed}')
    print(f'\n')


#---------------------------------------------------------------------------------
def virusTotalReport(apiKey, hash_md5):
    """Query VT for file info. Use V2 and V3 of API for all FREE info"""

    #Get API V3 info
    try:
        client = vt.Client(f'{apiKey}')
        file = client.get_object(f'/files/{hash_md5.hexdigest()}')
        

    except vt.error.APIError:
        print(f'[{Fore.RED}!{Style.RESET_ALL}] Virus Total report unavailable.\n\n')
        client.close()
        return

    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Virus Total report available:\n\n')
    pe = file.get("pe_info")

    
    imports = pe.get("import_list")
    sections = pe.get("sections")
    entryPoint = pe.get("entry_point")

    print(f'VirusTotal Report\n{"-"*70}\n')

    print(f'Sections\n{"-"*70}')
    print(f'    {("Name"):10}{("Entropy"):10}{("R_Size"):10}{("V_Size"):9}{("Flags")}\n    {"-"*44}\n')
    for entry in sections:
        print(f'    {(entry["name"]):6}{(entry["entropy"]):10}{(entry["raw_size"]):10}{(entry["virtual_size"]):10}     {(entry["flags"]):5}')
    print(f"\n\n")
    
    print(f'Libraries/Imports\n{"-"*70}')

    
    for entry in imports:
        for x in range(len(list(entry.values())[1])):
            print(f'    {(list(entry.values())[0] if x == 0 else ""):25}{(list(entry.values())[1])[x]}')
        print("")
        
    client.close()

    #Get V2 vendor detection data
    try:
        url = 'https://virustotal.com/vtapi/v2/file/report'
        parameters = {'apikey': '362793d7648c596f8bd4ddcf35e2c8a24c810fc7401153453085bcfbd1fabbc2', 'resource': '247705d987c18bd67702a8442ee0fce6028e1973951786052e8ed5897b007707'}
        response = requests.get(url, params=parameters)
        response = response.json()

        if response['response_code'] == 1:

            scans = response['scans']
            date = response['scan_date']
            total = response['total']
            positives = response['positives']

            print(f'Detection\n{"-"*70}')
            print(f'    {"Scan Date: ":34} {date}')
            print(f'    {"Detected: ":35}{positives}/{total}\n\n')
            print(f'    {"Vendor":25}{"Detected":10}{"Result"}\n    {"-" * 66}\n')

            for key, value in scans.items():
                print(f'    {key:25}{str(bool(value["detected"])):10}{value["result"]}')
            print(f"    {'-' * 70}")

    except requests.ConnectionError as err:
        print(f"[-] Error connecting to VirusTotal: {err}")



#---------------------------------------------------------------------------------
def graphic():
    """Print cheesy graphic"""

    print(f"         {Fore.GREEN}                    ____")
    print(f"           ____  ____  ___  / __ \\____  ____________  _____")
    print(f"          / __ \/ __ \\/ _ \/ /_/ / __ \/ ___/ __/ _ \\/ ___/")
    print(f"         / /_/ / /_/ /  __/ ____/ /_/ / /  (__ )  __/ /")
    print(f"         \\__,_/ .___/\___/_/    \\__,_/_/  /___/\\___/_/")
    print(f"             /_/{Style.RESET_ALL}\n\n\n")


#---------------------------------------------------------------------------------
def getOptionalHeaderData(pe):
    """Get Optional Header info"""

    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Image Base:                   {hex(pe.OPTIONAL_HEADER.ImageBase)}')
    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] E_lfanew:                     {hex(pe.DOS_HEADER.e_lfanew)}')
    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Entry Point:                  {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}')
    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] Size of Image (bytes):        {(pe.OPTIONAL_HEADER.SizeOfImage)}')
    


#---------------------------------------------------------------------------------
def getStrings(args):
    """Print file strings to separate file <default=peStrings.txt>"""

    os.system(f'strings {args.file} > {args.strings}')


#---------------------------------------------------------------------------------
def getEntropy(args):
    """Get file entropy and predict if packed"""

    packed = ''

    with open(args.file, 'rb') as f:
        data = f.read()

    entropy = 0
    for x in range(256):
        per = float(data.count(x))/len(data)
        if per > 0:
            entropy += - per * math.log(per, 2)

    if entropy > 6:
        packed = 'Possibly Packed'
    if entropy > 7:
        packed = 'Likely Packed'

    print(f'[{Fore.GREEN}+{Style.RESET_ALL}] {"Entropy of file: ":30s}{entropy:.3f}        {packed}')
    

#---------------------------------------------------------------------------------
def main():
    """Main"""

    args = get_args()
    pe = pefile.PE(args.file)
    impHash = pe.get_imphash()
    apiKey = "<your API key>"

    graphic()
    getStrings(args)
    print(f'\nSummary for:  {args.file} \n' + '-' * (len(args.file) + 14))
    hash_md5 = getHashes(args, impHash)
    getEntropy(args)
    getOptionalHeaderData(pe)
    getSections(pe)
    getImports(pe)
    virusTotalReport(apiKey, hash_md5)
    print(f'\n\n[{Fore.GREEN}+{Style.RESET_ALL}] Summary Complete.\n\n')


if __name__ == '__main__':
        main()
