import tkinter as tk
from tkinter import messagebox

nest= tk.Tk()
nest.title("Message or dialog boxes and boxes")

def message(): 
    #Messagebox.Showinfo ("information", "first message")
    print("hi")

btn1= tk.Button(nest, text="First button", command=message)
#btn1.pack()
btn1.place(x=15, y=30)
nest.geometry("300x300")

nest.resizable(False, False)
nest.mainloop()