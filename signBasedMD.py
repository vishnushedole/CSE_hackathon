import hashlib
import mysql.connector
import os.path
import pefile
from sklearn.metrics import confusion_matrix
import joblib 
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import pandas as pd
import numpy as np

mydb = mysql.connector.connect(
host="localhost",
 user="root",
 passwd="vishnu123!@#S",
 database="siganturesdb"
)

file = ""
file_stack = []
malicious_files = []
Data = pd.read_csv(r"C:\Users\vaishnavi\Downloads\CSE_hackathon-main\tkinter\MalwareData.csv",sep="|")
Data.info()

# Separation of Malware and Legit data

legit_data = Data[0:41323]
mal_data = Data[41324:]
print("Legit files dataset :",legit_data.shape)
print("Malware files dataset :",mal_data.shape)

# Cleaning data 

New_Data = Data.drop(['Name','md5'],axis=1).values

# Attribute selection


df = pd.DataFrame(New_Data)
corr_mat = df.corr()
attribute_list = corr_mat[54]
selected_att = []

sum = 0

for i in range(54):
    sum+=attribute_list[i]
    
avg = sum/54
not_selected = []

for i in range(55):
    if attribute_list[i]>avg:
        selected_att.append(i)
    else:
        not_selected.append(i)

not_selected.append(54)
new_df = df.drop(df.columns[not_selected],axis=1)
for i in range(22):
    print(i," ",Data.columns[selected_att[i]+2]," ",attribute_list[selected_att[i]])

# Spliting data set into training and testing data.
# Training Model using training data

labels = Data['legitimate'].values

legit_train,legit_test,mal_train,mal_test =train_test_split(new_df,labels,test_size=0.2)
classifier1 = RandomForestClassifier()
classifier1.fit(legit_train,mal_train)

# # Printing accuracy of the model
print("The accuracy of the model is ",classifier1.score(legit_test,mal_test)*100)

# Confusion matrix 
result = classifier1.predict(legit_test)
conf_mat = confusion_matrix(mal_test,result)
print(conf_mat)


# Precision
precision = conf_mat[0][0]/(conf_mat[0][0]+conf_mat[0][1])
print("Model precision is : ",precision)

# # Recall
recall = conf_mat[0][0]/(conf_mat[0][0]+conf_mat[1][0])
print("Model recall is :",recall)

# # F1-score
F1_score = (2*precision*recall)/(precision+recall)
print("F1-score :",F1_score)


def randomForest(filePath):
	print(filePath)
	classifier = joblib.load('model.sav')
	avg_values = new_df.mean()
	avg_values = pd.DataFrame(avg_values)
	pe = pefile.PE(filePath)
	avg_SectionsMinRawsize = avg_values.iloc[12].values[0]
	avg_SectionsMinVirtualsize = avg_values.iloc[13].values[0]
	avg_ImportsNbDLL = avg_values.iloc[14].values[0]
	avg_ImportsNb = avg_values.iloc[15].values[0]
	avg_ImportsNbOrdinal = avg_values.iloc[16].values[0]
	avg_ExportNb = avg_values.iloc[17].values[0]
	avg_ResourcesNb = avg_values.iloc[18].values[0]
	avg_ResourcesMinEntropy = avg_values.iloc[19].values[0]
	avg_VersionInformationSize = avg_values.iloc[19].values[0]
	sample = [pe.FILE_HEADER.Machine,pe.FILE_HEADER.SizeOfOptionalHeader,pe.FILE_HEADER.Characteristics,pe.OPTIONAL_HEADER.MajorLinkerVersion,pe.OPTIONAL_HEADER.SizeOfCode,pe.OPTIONAL_HEADER.ImageBase,pe.OPTIONAL_HEADER.FileAlignment,pe.OPTIONAL_HEADER.MajorImageVersion,pe.OPTIONAL_HEADER.MinorImageVersion,pe.OPTIONAL_HEADER.MajorSubsystemVersion,pe.OPTIONAL_HEADER.SizeOfHeaders,pe.OPTIONAL_HEADER.Subsystem,avg_SectionsMinRawsize,avg_SectionsMinVirtualsize,avg_ImportsNbDLL,avg_ImportsNb,avg_ImportsNbOrdinal,avg_ExportNb,avg_ResourcesNb,avg_ResourcesMinEntropy,avg_VersionInformationSize]
	sample = pd.DataFrame([sample],columns=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20])
	if(classifier.predict(sample.values)[0]):
		print("The file specified by the path "+ filePath + " is SAFE")
	else:
         print("Malicious file!!")
         malicious_files.append(filePath)
	

def search(signature):
   
    mycursor = mydb.cursor()
    query = 'select * from siganturesdb.hash_table where Hashcode = %s;'
    mycursor.execute(query,[signature])
    output = mycursor.fetchall()
    if(len(output)):
        print(output)
        print("is malicious")
    else:
        filename = file_stack.pop()
        if filename.endswith(".exe") or filename.endswith(".dll"):
         randomForest(filename)
        else :
            print("Not an exe file")
   
        
        
def readFile(filePath):
    global file 
    file = filePath
    print("Inside readifle function")
    BLOCK_SIZE = 65536 
    if(os.path.isfile(file)):
        file_stack.append(file)
        file_hash = hashlib.sha256() 
        with open(file, 'rb') as f: 
            fb = f.read(BLOCK_SIZE) 
            while len(fb) > 0: 
                file_hash.update(fb) 
                fb = f.read(BLOCK_SIZE) 
        signature = file_hash.hexdigest()
        
        search(signature)
    elif(os.path.isdir(file)):
        filesList = os.listdir(file)
        print(filesList)
        fname = ""
        for i in range(len(filesList)):
            newPath = file + "/" + filesList[i]
            if(os.path.isdir(newPath)):
                readFile(newPath)
            else:
                file_stack.append(newPath)
                file_hash = hashlib.sha256() 
                with open(newPath, 'rb') as f: 
                    fb = f.read(BLOCK_SIZE) 
                    while len(fb) > 0: 
                        file_hash.update(fb) 
                        fb = f.read(BLOCK_SIZE) 
                signature = file_hash.hexdigest()
                
                search(signature)
    else:
        print("No such file or directory")
    return len(malicious_files)
# readFile(file)