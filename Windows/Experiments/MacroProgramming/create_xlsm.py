import os
from docx import Document
import win32com.client as win32

# needs    pip install openpyxl pywin32
# Create an Excel document using python-docx
# needs to be run on Windows and not linux
wb = Workbook()
ws = wb.active
ws.title = "Sheet1"
ws['A1'] = 'Hello'
ws['A2'] = 'World'
excel_path = 'example.xlsm'
wb.save(excel_path)

# Define the path to the macro file (a text file containing VBA code)
macro_file_path = 'macro.txt'

# Read the macro content from the text file
with open(macro_file_path, 'r') as file:
    macro_code = file.read()

# Add the macro to the Excel workbook using win32com.client
excel = win32.Dispatch('Excel.Application')
excel.Visible = False

# Open the workbook
workbook = excel.Workbooks.Open(os.path.abspath(excel_path))

# Add a new module to the workbook and insert the macro code
vb_module = workbook.VBProject.VBComponents.Add(1)  # 1 indicates a standard module
vb_module.CodeModule.AddFromString(macro_code)

# Save and close the workbook
workbook.Save()
workbook.Close()

# Quit the Excel application
excel.Quit()