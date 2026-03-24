import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from tkinterdnd2 import TkinterDnD, DND_FILES
import base64, re, codecs, urllib.parse, hashlib, os, pyperclip
from datetime import datetime

# ---------------- Global Variables ---------------- #
last_results = []

# ---------------- Style ---------------- #
BG_COLOR = "#1E1E2F"
FG_COLOR = "#FFFFFF"
FONT_TITLE = ("Segoe UI", 18, "bold")
FONT_LABEL = ("Segoe UI", 11)
FONT_BTN = ("Segoe UI", 10, "bold")
FONT_TEXT = ("Consolas", 10)

# ---------------- Detection Functions ---------------- #
def is_base64(s):
    try:
        if len(s) % 4 != 0: return False
        base64.b64decode(s, validate=True)
        return True
    except: return False
def is_hex(s): return bool(re.fullmatch(r'[0-9a-fA-F]+', s))
def is_url_encoded(s): return bool(re.search(r'%[0-9a-fA-F]{2}', s))
def is_binary(s): return bool(re.fullmatch(r'(?:[01]{8}\s*)+', s))
def detect_hash(s):
    if re.fullmatch(r'[a-fA-F0-9]{32}', s): return "MD5"
    if re.fullmatch(r'[a-fA-F0-9]{40}', s): return "SHA1"
    if re.fullmatch(r'[a-fA-F0-9]{64}', s): return "SHA256"
    return None

def analyze_string(text):
    results, decoded = [], []
    if is_base64(text):
        results.append("Base64"); decoded.append("Base64 → "+base64.b64decode(text).decode(errors='ignore'))
    if is_hex(text):
        results.append("Hex")
        try: decoded.append("Hex → "+bytes.fromhex(text).decode(errors='ignore'))
        except: pass
    if is_url_encoded(text):
        results.append("URL"); decoded.append("URL → "+urllib.parse.unquote(text))
    if is_binary(text):
        results.append("Binary"); decoded.append("Binary → "+''.join(chr(int(b,2)) for b in text.split()))
    rot = codecs.decode(text, 'rot_13')
    if rot != text: decoded.append("ROT13 → "+rot)
    h = detect_hash(text)
    if h: results.append(h + " Hash")
    return results, decoded

def generate_hashes(text):
    return [
        f"MD5: {hashlib.md5(text.encode()).hexdigest()}",
        f"SHA1: {hashlib.sha1(text.encode()).hexdigest()}",
        f"SHA256: {hashlib.sha256(text.encode()).hexdigest()}"
    ]

def hash_file(filepath):
    with open(filepath,"rb") as f: data=f.read()
    return {"MD5": hashlib.md5(data).hexdigest(),"SHA1": hashlib.sha1(data).hexdigest(),"SHA256": hashlib.sha256(data).hexdigest()}

def lookup_hash(hash_value):
    KNOWN_MALWARE_HASHES = {
        "5d41402abc4b2a76b9719d911017c592": "Test Malware",
        "e99a18c428cb38d5f260853678922e03": "Suspicious File"
    }
    return KNOWN_MALWARE_HASHES.get(hash_value.lower())

# ---------------- GUI Actions ---------------- #
def analyze_text():
    text = text_input.get("1.0", tk.END).strip()
    if not text: result_label.config(text="Enter text"); return
    results, decoded = analyze_string(text)
    hashes = generate_hashes(text)
    malware_hits = []
    for h in hashes:
        hv = h.split(":")[1].strip()
        res = lookup_hash(hv)
        if res: malware_hits.append(f"⚠ Malware: {res}")
    output=[]
    if decoded: output.append("=== DECODED ==="); output.extend(decoded)
    output.append("\n=== HASHES ==="); output.extend(hashes)
    if malware_hits: output.append("\n=== ALERT ==="); output.extend(malware_hits)
    result_label.config(text="\n".join(results) if results else "No encoding detected")
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END, "\n".join(output))

def scan_file():
    path=filedialog.askopenfilename()
    if not path: return
    findings=[]
    with open(path,"r",errors="ignore") as f:
        for i,line in enumerate(f,1):
            results, decoded = analyze_string(line.strip())
            if results:
                findings.append({"line":i,"text":line.strip(),"detections":results,"decoded":decoded})
    global last_results; last_results=findings
    result_label.config(text=f"{len(findings)} suspicious lines found")

def show_file_hashes():
    path=filedialog.askopenfilename(title="Select File")
    if not path: return
    hashes=hash_file(path)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END,f"=== FILE HASHES ({os.path.basename(path)}) ===\n\n")
    hash_text=""
    for algo,h in hashes.items():
        line=f"{algo}: {h}"
        output_text.insert(tk.END,line+"\n")
        hash_text+=line+"\n"
    result_label.config(text="Hashes generated and copied to clipboard")
    pyperclip.copy(hash_text)

def save_hash_report():
    path=filedialog.askopenfilename(title="Select File")
    if not path: return
    hashes=hash_file(path)
    filename=os.path.basename(path)
    timestamp=datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name=f"hash_report_{filename}_{timestamp}.txt"
    with open(report_name,"w") as f:
        f.write(f"File: {filename}\nTimestamp: {timestamp}\n\n")
        for algo,h in hashes.items(): f.write(f"{algo}: {h}\n")
    messagebox.showinfo("Saved",f"Hash report saved as {report_name}")

def verify_file():
    path=filedialog.askopenfilename(title="Select File")
    if not path: return
    hashes=hash_file(path)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END,f"=== FILE HASHES ({os.path.basename(path)}) ===\n\n")
    for algo,h in hashes.items(): output_text.insert(tk.END,f"{algo}: {h}\n")
    user_hash=simpledialog.askstring("Verify","Enter known hash (optional):")
    if user_hash:
        for algo,h in hashes.items():
            if h.lower()==user_hash.lower(): result_label.config(text=f"✅ MATCH FOUND ({algo})"); return
        result_label.config(text="❌ No Match")
    else:
        result_label.config(text="Hashes generated successfully")

def compare_two_files():
    path1=filedialog.askopenfilename(title="Select First File")
    if not path1: return
    path2=filedialog.askopenfilename(title="Select Second File")
    if not path2: return
    hashes1=hash_file(path1); hashes2=hash_file(path2)
    output_text.delete("1.0", tk.END)
    output_text.insert(tk.END,f"=== Comparing Files ===\n{os.path.basename(path1)}\n{os.path.basename(path2)}\n\n")
    all_match=True
    for algo in ["MD5","SHA1","SHA256"]:
        h1=hashes1[algo]; h2=hashes2[algo]
        if h1==h2: output_text.insert(tk.END,f"{algo}: ✅ Match\n")
        else: output_text.insert(tk.END,f"{algo}: ❌ Different\n"); all_match=False
    if all_match: result_label.config(text="✅ All hashes match. Files are identical")
    else: result_label.config(text="❌ Hash mismatch. Files differ")

def drop_file(event):
    path=event.data.strip("{}")
    text_input.delete("1.0", tk.END)
    text_input.insert(tk.END,path)
    scan_file()

# ---------------- Button Hover Effect ---------------- #
def on_enter(e):
    e.widget['bg'] = lighten_color(e.widget.original_bg, 30)
def on_leave(e):
    e.widget['bg'] = e.widget.original_bg
def lighten_color(hex_color, amount=30):
    hex_color = hex_color.lstrip('#')
    r, g, b = int(hex_color[0:2],16), int(hex_color[2:4],16), int(hex_color[4:6],16)
    r = min(255, r+amount); g = min(255, g+amount); b = min(255, b+amount)
    return f"#{r:02X}{g:02X}{b:02X}"

# ---------------- GUI ---------------- #
root=TkinterDnD.Tk()
root.title("Mini Digital Forensic Suite")
root.geometry("1100x750")
root.configure(bg=BG_COLOR)

# ----- Header -----
header = tk.Label(root, text="🔥 Mini Digital Forensic Suite 🔥",
                  font=("Segoe UI", 24, "bold"),
                  bg=BG_COLOR, fg="#00FFAA")
header.pack(pady=15)

# Buttons Frame
btn_frame = tk.Frame(root, bg=BG_COLOR)
btn_frame.pack(pady=10)
buttons = [
    ("Analyze", analyze_text, "#4CAF50"),
    ("Scan File", scan_file, "#2196F3"),
    ("Show Hashes", show_file_hashes, "#FF9800"),
    ("Save Hash Report", save_hash_report, "#795548"),
    ("Verify File", verify_file, "#9C27B0"),
    ("Compare Two Files", compare_two_files, "#F44336")
]
for i, (text, cmd, color) in enumerate(buttons):
    btn = tk.Button(btn_frame, text=text, command=cmd, bg=color, fg="white",
                    font=FONT_BTN, width=18)
    btn.original_bg = color
    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)
    btn.grid(row=0, column=i, padx=5, pady=5)

# Input Text
tk.Label(root, text="Enter Suspicious Text / Drop File:", bg=BG_COLOR, fg=FG_COLOR, font=FONT_LABEL).pack(anchor="w")
text_input = tk.Text(root, height=5, width=135, font=FONT_TEXT, bg="#2D2D44", fg=FG_COLOR, insertbackground=FG_COLOR)
text_input.pack()
text_input.drop_target_register(DND_FILES)
text_input.dnd_bind('<<Drop>>', drop_file)

# Results Label
result_label = tk.Label(root, text="", bg=BG_COLOR, fg="#FFD700", justify="left", font=FONT_TEXT)
result_label.pack(fill="x", pady=5)

# Output Text
output_text = tk.Text(root, height=25, width=135, font=FONT_TEXT, bg="#2D2D44", fg=FG_COLOR, insertbackground=FG_COLOR)
output_text.pack()

root.mainloop()