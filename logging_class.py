
'''This program will make a log class with function name log which will be called in the different files'''
class log_data():
    def log(self,filename,date_time,username,message):                  # creates a function log
        filename_complete = str(filename) + '_log.txt'                  # concatenates user entered filename with .txt -> that makes a new file with the given username 
        filename_complete = "Logs/" + filename_complete
        file_obj = open(filename_complete,'a')                          # open the file in append mode -> so previous data is not erased
        file_obj.write(f'{date_time}::INFO::{username}::{message}\n')   # write data in this format to a file
        file_obj.close()                                                # after successful writeup in a file close the file with .close() fucntion
