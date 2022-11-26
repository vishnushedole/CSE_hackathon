import hashlib
import mysql.connector
import os.path
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  passwd="Ravi@123",
  database="siganturesdb"
)

file = r"C:\Users\tejas\OneDrive\Desktop\programming\kit\pointer.c"

def search(signature):
    mycursor = mydb.cursor()
    query = 'select * from siganturesdb.hash_table where Hashcode = %s;'
    mycursor.execute(query,[signature])
    output = mycursor.fetchall()
    if(len(output)):
        print(output)
        print("is malicious")
   
        
        
def readFile(file):
    print("Inside readifle function")
    BLOCK_SIZE = 65536 
    if(os.path.isfile(file)):
        
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
        for i in range(len(filesList)):
            newPath = file + "\\" + filesList[i]
            if(os.path.isdir(newPath)):
                readFile(newPath)
            else:
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
readFile(file)