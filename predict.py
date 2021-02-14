#!/usr/bin/env python
# coding: utf-8

# In[1]:


import os
import re
import pandas as pd
import numpy as np
import random
import json
import sys
from sklearn import tree
from sklearn.preprocessing import LabelEncoder
import matplotlib.pyplot as plt
import pickle
from sklearn.ensemble import RandomForestClassifier


# In[2]:


# parameter
feature_order = ['login_query_ratio', 'select_query_ratio',                'dest_byte_avg',                 'dest_port_80_ratio', 'dest_port_dis',                'event_out_success', 'process_name_cmd', 'process_name_xampp']
sample_line_num = 10000
QUICK_MODE = False
targetfolder = sys.argv[1]
# targetfolder = "./Example_Test"
if len(sys.argv) > 2:
    model_filename = sys.argv[2]
else:
    model_filename = "./model_final.pkl"

print("target path", targetfolder)
print("model path", model_filename)


# In[3]:


def file_len(fname):
    with open(fname) as f:
        for i, l in enumerate(f):
            if QUICK_MODE and i > sample_line_num:
                break
            pass
    return i + 1
def sameplefileline(filepath, linenum):
    special_line = 0
    filelen = file_len(filepath)
    print("sameple rate", min(1, linenum/filelen))
    with open(filepath) as readfile:
        head = ""
        if linenum > filelen:
            for x in range(filelen):
                head = head + next(readfile)
        else:
            samepleline = sorted(random.sample(range(filelen), linenum))
            for x in range(filelen):
                if x in samepleline:
                    samepleline.pop(samepleline.index(x))
                    head = head + next(readfile)
                    if len(samepleline) == 0:
#                         print("break at", x)
                        break
                else:
                    tmp_line = next(readfile)
                    if special_line > linenum/2:
                        continue
                    if re.search("select[^a-z]|from[^a-z]", tmp_line, flags=re.I):
                        head = head + tmp_line
                        special_line = special_line + 1
                    elif re.search("password[^a-z]|username[^a-z]", tmp_line, flags=re.I):
                        head = head + tmp_line
                        special_line = special_line + 1

        return head
def parse_data(filename):
    tmpdf = pd.read_json(filename, lines=True)
    tmpjson = json.loads(tmpdf.to_json(orient='records'))
    nor = pd.json_normalize(tmpjson)
    return nor, nor.columns


# In[4]:


def distrubuted(df_col):
    vc = df_col.value_counts(normalize=True, sort=False, dropna=False)
    return (np.array(vc)**2).sum()
def match_value_vc(df_col, value):
    i=0.0
    vc = df_col.value_counts(normalize=True, sort=False, dropna=False)
    for x in vc.index:
        if re.search(value, str(x), flags=re.I):
            i+=vc[x]
        else:
            pass
    return i
def packetbeat_feature_extract(df, folder):
    tmp_dict = {}
    if 'url.query' in df.columns:
        tmp_dict['select_query_ratio'] = match_value_vc(df['url.query'], "select[^a-z]|from[^a-z]")
        tmp_dict['login_query_ratio'] = match_value_vc(df['url.query'], "password[^a-z]|username[^a-z]")
    else:
        tmp_dict['select_query_ratio'] = 0
        tmp_dict['login_query_ratio'] = 0
    df_return = pd.DataFrame()
    tmp_dict['dest_byte_avg'] = df['destination.bytes'].mean()
    tmp_dict['dest_byte_var'] = df['destination.bytes'].var()
    tmp_dict['dest_port_80_ratio'] = len(df[df['destination.port'] == 80])/len(df)
    tmp_dict['dest_port_443_ratio'] = len(df[df['destination.port'] == 443])/len(df)
    tmp_dict['dest_port_dis'] = distrubuted(df['destination.port'])
    tmp_dict['dest_ip_dis'] = distrubuted(df['destination.ip'])
    tmp_dict['folder'] = folder
    df_return = df_return.append(tmp_dict, ignore_index=True)
    return df_return
def winlog_feature_extract(df, folder):
    tmp_dict = {}
    df_return = pd.DataFrame()
    tmp_dict['process_name_xampp'] = match_value_vc(df['winlog.event_data.ProcessName'], "xampp")
    tmp_dict['process_name_browser'] = match_value_vc(df['winlog.event_data.ProcessName'], "explorer|chorme|firefox")
    tmp_dict['process_name_cmd'] = match_value_vc(df['winlog.event_data.ProcessName'], "cmd")
    tmp_dict['event_code_dis'] = distrubuted(df['event.code'])
    tmp_dict['event_out_success'] = len(df[df['event.outcome'] == "success"])/len(df)
    tmp_dict['folder'] = folder

    df_return = df_return.append(tmp_dict, ignore_index=True)
    return df_return
def predict(folderpath):
    data = sameplefileline(folderpath + "/packetbeat.json", sample_line_num)
    tmp_df, col = parse_data(data)
    feature_df_pack = packetbeat_feature_extract(tmp_df, folderpath)

    tmp_df, _= parse_data(folderpath + "/winlogbeat.json")
    feature_df_win = winlog_feature_extract(tmp_df, folderpath)
    feature_df = feature_df_pack.merge(feature_df_win)
#     print(feature_df)
    return feature_df


# In[5]:


predict_df = pd.DataFrame()
foldername_lis = []
files = os.listdir(targetfolder)
files.sort()
for foldername in files:
    print(targetfolder+"/"+foldername)
    tmp_df = predict(targetfolder+"/"+foldername)
    foldername_lis.append(foldername)
    predict_df = predict_df.append(tmp_df, ignore_index=True)


# In[6]:


with open(model_filename, 'rb') as file:
    clf = pickle.load(file)

predict_df = predict_df[feature_order]
ans = clf.predict(predict_df)
for i in range(len(ans)):
    pid = foldername_lis[i].split('_')[-1]
    print("testcase", pid + ":", ans[i])


# In[ ]:




