import tkinter as tk
import os

def copy_to_clipboard(text):
    root = tk.Tk()
    root.withdraw()
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()
    root.destroy()

def is_file_path(path):
    return os.path.exists(path)

# def file_or_msg(input):
#     if is_file_path(input):
#         print(f'[DEBUG]: this is file')

#         return t