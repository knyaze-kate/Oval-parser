import tkinter as tk
from tkinter import filedialog, messagebox
from lxml import etree
import json
import os


def parse_oval(file_path):
    try:
        tree = etree.parse(file_path)
        root = tree.getroot()
        print("Successfully parsed the XML file")
    except OSError as e:
        messagebox.showerror("Error", f"Error reading file: {e}")
        return []

    namespaces = {
        'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
        'red-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux'
    }

    vulnerabilities = []

    def parse_criteria(criteria, root):
        elements = []
        for criterion in criteria.findall('oval:criterion', namespaces):
            test_ref = criterion.get('test_ref')
            if test_ref:
                test = root.find(f".//*[@id='{test_ref}']", namespaces)
                if test is not None:
                    test_id = test.get('id')
                    comment = criterion.get('comment', "No comment")
                    object_ref_element = test.find('.//red-def:object', namespaces)
                    if object_ref_element is not None:
                        object_ref = object_ref_element.get('object_ref')
                        object = root.find(f".//*[@id='{object_ref}']", namespaces)
                        if object is not None:
                            object_name_elem = object.find('red-def:name', namespaces)
                            object_name = object_name_elem.text if object_name_elem is not None else None
                        else:
                            object_name = None
                    else:
                        object_name = None

                    state_ref_element = test.find('.//red-def:state', namespaces)
                    state_version = None
                    if state_ref_element is not None:
                        state_ref = state_ref_element.get('state_ref')
                        state = root.find(f".//*[@id='{state_ref}']", namespaces)
                        if state is not None:
                            state_version = state.get('version', None)

                    elements.append({
                        "test_ref": test_ref,
                        "details": {
                            "id": test_id,
                            "comment": comment,
                            "object_name": object_name,
                            "state_version": state_version
                        }
                    })

        for sub_criteria in criteria.findall('oval:criteria', namespaces):
            operator = sub_criteria.get('operator', 'AND')
            sub_elements = parse_criteria(sub_criteria, root)
            elements.append({
                "operator": operator,
                "elements": sub_elements
            })

        return elements

    definitions = root.findall('.//oval:definition', namespaces)[:3]

    for definition in definitions:
        vuln_class = definition.get('class', "patch")
        vuln_id = definition.get('id')
        title_elem = definition.find('.//oval:title', namespaces)
        title = title_elem.text if title_elem is not None else "N/A"

        criteria = definition.find('.//oval:criteria', namespaces)
        if criteria is not None:
            elements = parse_criteria(criteria, root)
        else:
            elements = []

        ref_elems = definition.findall('.//oval:reference', namespaces)
        references = []
        for ref in ref_elems:
            references.append({
                "ref_id": ref.get('ref_id'),
                "ref_url": ref.get('ref_url'),
                "source": ref.get('source')
            })

        description_elem = definition.find('.//oval:description', namespaces)
        description = description_elem.text if description_elem is not None else "N/A"

        descriptions_elem = definition.find('.//oval:descriptions', namespaces)
        if descriptions_elem is not None:
            description_list = [desc.text for desc in descriptions_elem.findall('.//oval:description', namespaces)]
            description = ' '.join(description_list) if description_list else "N/A"

        updated_elem = definition.find('.//oval:updated', namespaces)
        updated_date = updated_elem.get('date') if updated_elem is not None else "N/A"


        # Инициализация cvss
        cvss = None

        # Поиск элементов cve
        print(f"Looking for CVE elements in definition ID: {vuln_id}")

        # Проверка наличия <metadata>
        metadata_elem = definition.find('.//oval:metadata', namespaces)
        if metadata_elem is not None:
            print(f"Metadata element found for definition ID: {vuln_id}")
        else:
            print(f"No metadata element found for definition ID: {vuln_id}")

        # Проверка наличия <advisory>
        advisory_elem = metadata_elem.find('.//oval:advisory', namespaces)
        if advisory_elem is not None:
            print(f"Advisory element found for definition ID: {vuln_id}")
        else:
            print(f"No advisory element found for definition ID: {vuln_id}")

        # Поиск <cve> внутри <advisory>
        cve_elems = advisory_elem.findall('.//oval:cve', namespaces) if advisory_elem is not None else []
        if cve_elems:
            print(f"Found {len(cve_elems)} CVE elements in definition ID: {vuln_id}")
            for cve_elem in cve_elems:
                print(f"CVE element: {etree.tostring(cve_elem, pretty_print=True, encoding='unicode')}")
                cvss = cve_elem.attrib.get('cvss3')
                if cvss:
                    print(f"CVSS value found: {cvss}")
                    break
        else:
            print(f"No CVE elements found for definition ID: {vuln_id}")

        if cvss is None:
            print(f"No CVSS found for definition ID: {vuln_id}")
        else:
            print(f"CVSS found for definition ID: {vuln_id}: {cvss}")

        print(f"Parsed definition ID: {vuln_id}, Title: {title}, CVSS: {cvss}")

        vulnerability = {
            "class": vuln_class,
            "id": vuln_id,
            "title": title,
            "references": references,
            "description": description,
            "updated_date": updated_date,
            "cvss": cvss,
            "criteria": {
                "operator": "OR",
                "elements": elements
            }
        }
        vulnerabilities.append(vulnerability)

    return vulnerabilities


def load_file():
    file_path = filedialog.askopenfilename(filetypes=[("XML Files", "*.xml")])
    if not file_path:
        return
    file_path_var.set(file_path)


def execute_analysis():
    file_path = file_path_var.get()
    if not file_path:
        messagebox.showerror("Error", "No file selected.")
        return

    if not file_path.endswith('.xml'):
        messagebox.showerror("Error", "Selected file is not an XML file.")
        return

    status_var.set("Processing...")
    app.update_idletasks()

    vulnerabilities = parse_oval(file_path)
    if vulnerabilities:
        vulnerabilities_json = json.dumps(vulnerabilities, indent=4)
        output_text.delete(1.0, tk.END)
        output_text.insert(tk.END, vulnerabilities_json)

        output_file_path = os.path.join(os.path.dirname(file_path), 'vulnerabilities_output_fixed.json')
        with open(output_file_path, 'w') as f:
            f.write(vulnerabilities_json)

        status_var.set(f"File saved at: {output_file_path}")
        messagebox.showinfo("Success", "File parsed successfully!")
    else:
        status_var.set("Error processing file.")
        messagebox.showerror("Error", "No vulnerabilities found.")


def clear_output():
    output_text.delete(1.0, tk.END)
    status_var.set("")


app = tk.Tk()
app.title("Обработка файла OVAL")
app.geometry("1200x800")  # Устанавливаем начальный размер окна
app.resizable(True, True)  # Позволяем изменять размер окна
app.configure(bg='lightyellow')

frame = tk.Frame(app)
frame.pack(pady=10)

file_path_var = tk.StringVar()
status_var = tk.StringVar()

load_button = tk.Button(frame, text="Загрузка файла", command=load_file)
load_button.pack(side=tk.LEFT, padx=5)

file_path_label = tk.Label(frame, textvariable=file_path_var)
file_path_label.pack(side=tk.LEFT, padx=5)

execute_button = tk.Button(frame, text="Выполнить", command=execute_analysis)
execute_button.pack(side=tk.LEFT, padx=5)

clear_button = tk.Button(frame, text="Очистить поле", command=clear_output)
clear_button.pack(side=tk.LEFT, padx=5)

text_frame = tk.Frame(app)
text_frame.pack(pady=10, expand=True, fill=tk.BOTH)

output_text = tk.Text(text_frame, wrap=tk.NONE, width=140, height=40)  # Увеличиваем размер текстового поля
output_text.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)

# Добавляем вертикальный и горизонтальный скроллбары
v_scrollbar = tk.Scrollbar(text_frame, orient=tk.VERTICAL, command=output_text.yview)
v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

h_scrollbar = tk.Scrollbar(app, orient=tk.HORIZONTAL, command=output_text.xview)
h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

output_text.config(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

status_label = tk.Label(app, textvariable=status_var)
status_label.pack(pady=5)

app.mainloop()
