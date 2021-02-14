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
sample_line_num = 2000
QUICK_MODE = False
CREATE_CASE_NUM = 40
targetfolder = sys.argv[1]
pkl_filename = sys.argv[2]
# targetfolder = "../Train"


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
#     print("sameple rate", min(1, linenum/filelen))
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
def packetbeat_feature_extract(df, attacktype):
    tmp_dict = {}
    df_return = pd.DataFrame()
    if 'url.query' in df.columns:
        tmp_dict['select_query_ratio'] = match_value_vc(df['url.query'], "select[^a-z]|from[^a-z]")
        tmp_dict['login_query_ratio'] = match_value_vc(df['url.query'], "password[^a-z]|username[^a-z]")
    else:
        tmp_dict['select_query_ratio'] = 0
        tmp_dict['login_query_ratio'] = 0
    tmp_dict['dest_byte_avg'] = df['destination.bytes'].mean()
    tmp_dict['dest_byte_var'] = df['destination.bytes'].var()
    tmp_dict['dest_port_80_ratio'] = len(df[df['destination.port'] == 80])/len(df)
    tmp_dict['dest_port_443_ratio'] = len(df[df['destination.port'] == 443])/len(df)
    tmp_dict['dest_port_dis'] = distrubuted(df['destination.port'])
    tmp_dict['dest_ip_dis'] = distrubuted(df['destination.ip'])
    tmp_dict['attacktype'] = attacktype
    df_return = df_return.append(tmp_dict, ignore_index=True)
    return df_return
def winlog_feature_extract(df, attacktype):
    tmp_dict = {}
    df_return = pd.DataFrame()
    tmp_dict['process_name_xampp'] = match_value_vc(df['winlog.event_data.ProcessName'], "xampp")
    tmp_dict['process_name_browser'] = match_value_vc(df['winlog.event_data.ProcessName'], "explorer|chorme|firefox")
    tmp_dict['process_name_cmd'] = match_value_vc(df['winlog.event_data.ProcessName'], "cmd")
    tmp_dict['event_code_dis'] = distrubuted(df['event.code'])
    tmp_dict['event_out_success'] = len(df[df['event.outcome'] == "success"])/len(df)

    tmp_dict['attacktype'] = attacktype
    df_return = df_return.append(tmp_dict, ignore_index=True)
    return df_return


# In[4]:


merge_df_pack = pd.DataFrame()
merge_df_win = pd.DataFrame()
for foldername in os.listdir(targetfolder):
    if re.match("Attack*", foldername):
        for filename in os.listdir(targetfolder+ "/" + foldername):
            print(foldername, filename)
            attacktype = foldername.replace("_", " ").replace("A", "a")
            if filename == 'packetbeat.json':
                for i in range(CREATE_CASE_NUM):
                    print(i)
                    data = sameplefileline(targetfolder+ "/" + foldername + "/" + filename, sample_line_num)
                    tmp_df, col = parse_data(data)
                    feature_df = packetbeat_feature_extract(tmp_df, attacktype)
                    merge_df_pack = merge_df_pack.append(feature_df, ignore_index=True)
#                 print("skip packet")
            elif filename == 'winlogbeat.json':
#                 print("skip winlog")
                tmp_df, _= parse_data(targetfolder+ "/" + foldername + "/" + filename)
                feature_df = winlog_feature_extract(tmp_df, attacktype)
                merge_df_win = merge_df_win.append(feature_df, ignore_index=True)
            else:
                print('error')


# In[5]:


all_df = merge_df_pack.merge(merge_df_win)
# all_df.to_csv("./2000_10_data.csv", index=False)


# In[6]:


X = all_df.drop(columns=['attacktype'])
X = X[feature_order]
# print(X)
Y = merge_df_pack.attacktype
clf = RandomForestClassifier(n_estimators=100, max_depth=10, bootstrap=False)
clf.fit(X, Y)


# In[7]:


# fig, ax = plt.subplots(figsize=(10, 10))
# tree.plot_tree(clf, feature_names=X.columns,fontsize=10)
# plt.savefig('tree_high_dpi.jpg', dpi=100)


# In[8]:


with open(pkl_filename, 'wb') as file:
    pickle.dump(clf, file)


# In[ ]:




