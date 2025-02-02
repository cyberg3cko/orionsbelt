#!/usr/bin/env python3 -tt
import argparse
import os
import shutil
import sqlite3
import subprocess
import sys
import time

parser = argparse.ArgumentParser()
parser.add_argument("directory", nargs=1, help="directory of tanium databases")
#parser.add_argument("-K","--keyword_searching", nargs=1, help="conduct keyword searching")

args = parser.parse_args()
directory = args.directory
directory = directory[0]
#keywords = ["base64", "excutionpolicy", "noexit"]


def main():
    if os.path.isdir(directory):
        taniumdir = os.path.abspath(directory)
        for troot, tdirs, tfiles in os.walk(taniumdir):
            for tfile in tfiles:
                taniumfile = os.path.join(troot, tfile)
                if (os.path.isfile(taniumfile) and taniumfile.endswith(".db")):
                    print("\n  > Processing database '{}'...".format(taniumfile.split("/")[-1]))
                    taniumlogdir = "/".join(list(taniumfile.split("/"))[0:-1])
                    #database_items = sqlite3.connect(taniumfile).cursor().execute("SELECT name FROM sqlite_master WHERE type='view';")
                    views = ["CombinedEventsSummary", "DNSEventSummary", "DriverSummary", "FilePathSummary", "FileSummary", "HTTPSummary", "HashSummary", "LibrarySummary", "NetworkSummary", "ProcessPathSummary", "ProcessSummary", "ProcessWithParentSummary", "RegistrySummary", "SecurityEventSummary", "SignatureDataSummary"]
                    taniumdir = taniumfile.split(".db")[0]
                    if os.path.exists(taniumdir):
                        shutil.rmtree(taniumdir)
                    else:
                        pass
                    os.mkdir(os.path.join(taniumdir))
                    for view in views:
                        print("   > Processing view '{}'...".format(view))
                        if view == "SignatureDataSummary": # more variations of queries may be needed, if encountering 'sqlite3.OperationalError' with utf-8 errors
                            sql_query = "SELECT CAST(Subject as string) FROM {};" # 'Subject' is the column header
                        else:
                            sql_query = "SELECT * FROM {};"
                        view_content = sqlite3.connect(taniumfile).cursor().execute(sql_query.format(view)).fetchall()
                        view_length = len(view_content)
                        if view_length > 0:
                            with open(os.path.join(taniumdir, view+".csv"), "a") as dbview_csv:
                                if view == "CombinedEventsSummary":
                                    dbview_csv.write("process_table_id,process_path,timestamp,timestamp_raw,type,operation,detail\n")
                                else:
                                    pass
                                if view == "DNSEventSummary":
                                    dbview_csv.write("id,timestamp,process_table_id,pid,process_path,operation,query,response,login_user_name,user_name,group_name,timestamp_raw\n")
                                else:
                                    pass
                                if view == "DriverSummary":
                                    dbview_csv.write("timestamp,process_table_id,id_pid_process_path,path,hash_type_name,library_hash,login_user_name,group_name,signature_issuer,signature_subject,signature_status,signature_status,timestamp_raw\n")
                                else:
                                    pass
                                if view == "FilePathSummary":
                                    dbview_csv.write("id,real_path\n")
                                else:
                                    pass
                                if view == "FileSummary":
                                    dbview_csv.write("id,timestamp,timestamp_raw,pid,process_table_id,process_path,file,real_path,operation,event_operation_id,login_user_name,user_name,group_name,details\n")
                                else:
                                    pass
                                if view == "HTTPSummary":
                                    dbview_csv.write("id,timestamp,process_table_id,pid,process_path,connection_id,local_address,remote_address,header_name,header_value,login_user_name,user_name,group_name,timestamp_raw\n")
                                else:
                                    pass
                                if view == "HashSummary":
                                    dbview_csv.write("TYPE,id,hash_id,path,hash_type_name,hash_type,hash\n")
                                else:
                                    pass
                                if view == "LibrarySummary":
                                    dbview_csv.write("timestamp,process_table_id,id,pid,process_path,path,hash_type_name,library_hash,login_user_name,user_name,group_name,signature_issuer,signature_subject,signature_status,signature_status_text,timestamp_raw\n")
                                else:
                                    pass
                                if view == "NetworkSummary":
                                    dbview_csv.write("id,timestamp,process_table_id,pid,process_path,local_address,local_address_port,remote_address,remote_address_port,operation,event_operation_id,login_user_name,user_name,group_name,timestamp_raw\n")
                                else:
                                    pass
                                if view == "ProcessPathSummary":
                                    dbview_csv.write("process_table_id,pid,process_path,login_user_name,user_name,group_name\n")
                                else:
                                    pass
                                if view == "ProcessSummary":
                                    dbview_csv.write("create_time,end_time,exit_code,pid,unique_process_id,process_path,process_table_id,login_user_name,user_name,group_name,hash_type_name,process_hash,process_command_line,create_time_raw,end_time_raw,signature_issuer,signature_subject,sigature_status,signature_status_text\n")
                                else:
                                    pass
                                if view == "ProcessWithParentSummary":
                                    dbview_csv.write("create_time,end_time,exit_code,pid,process_path,process_table_id,parent_process_table_id,parent_id,login_user_name,user_name,group_name,hash_type_name,hash,process_command_line,process_signature_issuer,process_signature_subject,process_sigature_status,process_signature_status_text,parent_path,parent_command_line,parent_hash,create_time_raw,end_time_raw\n")
                                else:
                                    pass
                                if view == "RegistrySummary":
                                    dbview_csv.write("id,timestamp,process_table_id,pid,process_path,key_path,value_name,operation,event_operation_id,login_user_name,user_name,group_name,timestamp_raw\n")
                                else:
                                    pass
                                if view == "SecurityEventSummary":
                                    dbview_csv.write("id,timestamp,process_table_id,pid,process_path,event_id,task_id,record_id,name,string,login_user_name,user_name,group_name,timestamp_raw,event_name\n")
                                else:
                                    pass
                                if view == "SignatureDataSummary":
                                    dbview_csv.write("id,Issuer,Subject,status,status_text\n")
                                else:
                                    pass
                                for row in view_content:
                                    row = str(row).replace(", ",",")[1:-1]
                                    dbview_csv.write(row+"\n")
                        else:
                            pass
                    print("  > Completed '{}'\r".format(taniumfile.split("/")[-1]))
                else:
                    pass
        print("\n")
        """if keywords:
            csvdir = os.path.abspath(directory)
            print("\n\n  > Conducting keyword-searching...")
            for croot, cdirs, cfiles in os.walk(csvdir):
                for cfile in cfiles:
                    csvfile = os.path.join(croot, cfile)
                    if (os.path.isfile(csvfile) and csvfile.endswith(".csv")):
                        with open(csvfile) as csvread:
                            for line in csvread:
                                for keyword in keywords:
                                    if keyword.lower() in line.lower().strip():
                                        #print("     Keyword '{}' found in '{}' for '{}'".format(keyword, csvfile.split("/")[-1], csvfile.split("/")[-2]))
                                        print("     Keyword '{}' found: '{}'".format(keyword, line.split(",")[-1]))
                                        time.sleep(1)
                                    else:
                                        pass
                    else:
                        pass
            print("\n\n")
        else:
            pass"""
    else:
        print("\n '{}' is not a directory.\n  Please try again\n\n".format(directory))
        sys.exit()


if __name__ =="__main__":
    main()