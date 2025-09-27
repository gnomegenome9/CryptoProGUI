import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import os
import json
from datetime import datetime
import tempfile
import shutil
import zipfile

CONFIG_FILE = "config.json"
LOG_FILE = "app.log"

# ======== Логирование ========
def log_message(message):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")

# ======== Конфиг ========
def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def save_config(config):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

def get_cryptcp_path(force_choose=False):
    config = load_config()
    path = config.get("cryptcp_path")
    if force_choose or not path or not os.path.exists(path):
        path = filedialog.askopenfilename(
            title="Выберите cryptcp.exe",
            filetypes=[("cryptcp.*.exe", "cryptcp.*.exe"), ("Все файлы", "*.*")]
        )
        if path:
            config["cryptcp_path"] = path
            save_config(config)
        else:
            messagebox.showerror("Ошибка", "Не выбран cryptcp.exe")
            return None
    return path

def change_cryptcp_path():
    path = get_cryptcp_path(force_choose=True)
    if path:
        messagebox.showinfo("Успех", f"Путь к cryptcp.exe обновлён:\n{path}")

# ======== Работа с файлами ========
selected_files = []

def choose_files():
    global selected_files
    selected_files = filedialog.askopenfilenames(
        title="Выберите файлы",
        filetypes=[("Все файлы", "*.*")]
    )
    listbox_files.delete(0, tk.END)
    for f in selected_files:
        listbox_files.insert(tk.END, f)

# ======== Безопасная распаковка ========
def safe_extract(zip_path, extract_dir):
    """
    Распаковка zip-архива с перекодировкой имён файлов (cp437 → cp866).
    Исправляет искажение кириллицы в названиях файлов.
    """
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for info in zf.infolist():
            try:
                # Попробуем перекодировать имя файла
                name = info.filename.encode('cp437').decode('cp866')
            except Exception:
                name = info.filename  # fallback

            target_path = os.path.join(extract_dir, name)
            os.makedirs(os.path.dirname(target_path), exist_ok=True)

            if not info.is_dir():
                with zf.open(info) as source, open(target_path, "wb") as target:
                    shutil.copyfileobj(source, target)

    log_message(f"{zip_path} → распакован в {extract_dir}")
    return extract_dir

# ======== Расшифровка и снятие подписи ========
def try_decrypt(cryptcp, path, output_path):
    cmd = [cryptcp, "-decrf", path, output_path, "-f", path]
    log_message(f"Попытка расшифровки: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode == 0:
        return True, "расшифровка выполнена"
    else:
        return False, (r.stderr.strip() or r.stdout.strip() or "Ошибка расшифровки")

def try_verify(cryptcp, path, output_path):
    cmd = [cryptcp, "-verify", path, output_path, "-f", path]
    log_message(f"Попытка проверки подписи: {' '.join(cmd)}")
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode == 0:
        return True, "подпись снята"
    else:
        return False, (r.stderr.strip() or r.stdout.strip() or "Ошибка проверки подписи")

def process_file_chain(cryptcp, file_path, save_dir):
    """
    Обрабатывает файл по цепочке расширений (.zip, .sig, .enc).
    Если файл — архив, финальные файлы сохраняются в подпапке с названием архива.
    Исходный архив удаляется после обработки.
    """
    messages = []
    temp_dir = tempfile.mkdtemp(prefix="proc_")
    final_results = []
    try:
        # очередь: (путь, относительный путь для сохранения)
        base_name = os.path.splitext(os.path.basename(file_path))[0]
        current_items = [(file_path, base_name)]

        while current_items:
            current_file, relname = current_items.pop(0)

            # --- ZIP ---
            if current_file.lower().endswith(".zip"):
                unpack_dir = os.path.join(temp_dir, relname)
                os.makedirs(unpack_dir, exist_ok=True)
                try:
                    safe_extract(current_file, unpack_dir)
                    messages.append(f"{os.path.basename(current_file)} → распакован")
                    log_message(f"{current_file} распакован в {unpack_dir}")
                    # все файлы из архива добавляем в очередь
                    for root, _, files in os.walk(unpack_dir):
                        for f in files:
                            full_path = os.path.join(root, f)
                            rel_path = os.path.join(relname, os.path.relpath(full_path, unpack_dir))
                            current_items.append((full_path, rel_path))
                    try:
                        os.remove(current_file)
                    except:
                        pass
                    continue
                except Exception as e:
                    messages.append(f"Ошибка распаковки {current_file}: {e}")
                    continue

            # --- SIG ---
            elif current_file.lower().endswith(".sig"):
                verified_tmp = os.path.join(temp_dir, os.path.splitext(os.path.basename(current_file))[0])
                ver_ok, ver_msg = try_verify(cryptcp, current_file, verified_tmp)
                if ver_ok:
                    messages.append(f"{os.path.basename(current_file)} → {ver_msg}")
                    log_message(f"{current_file} подпись снята -> {verified_tmp}")
                    new_rel = os.path.splitext(relname)[0]
                    current_items.insert(0, (verified_tmp, new_rel))
                    try:
                        os.remove(current_file)
                    except:
                        pass
                    continue
                else:
                    messages.append(f"{os.path.basename(current_file)} → ошибка подписи: {ver_msg}")

            # --- ENC ---
            elif current_file.lower().endswith(".enc"):
                decrypted_tmp = os.path.join(temp_dir, os.path.splitext(os.path.basename(current_file))[0])
                dec_ok, dec_msg = try_decrypt(cryptcp, current_file, decrypted_tmp)
                if dec_ok:
                    messages.append(f"{os.path.basename(current_file)} → {dec_msg}")
                    log_message(f"{current_file} расшифрован -> {decrypted_tmp}")
                    new_rel = os.path.splitext(relname)[0]
                    current_items.insert(0, (decrypted_tmp, new_rel))
                    try:
                        os.remove(current_file)
                    except:
                        pass
                    continue
                else:
                    messages.append(f"{os.path.basename(current_file)} → ошибка расшифровки: {dec_msg}")

            # --- Финальный файл ---
            out_full = os.path.join(save_dir, relname)
            os.makedirs(os.path.dirname(out_full), exist_ok=True)
            shutil.copy2(current_file, out_full)
            messages.append(f"Финальный файл сохранён: {out_full}")
            final_results.append(out_full)

        return True, messages
    except Exception as e:
        log_message(f"Ошибка при обработке {file_path}: {e}")
        return False, [f"Исключение: {e}"]

    finally:
        try:
            shutil.rmtree(temp_dir)
        except:
            pass

def process_files():
    cryptcp = get_cryptcp_path()
    if not cryptcp:
        return
    if not selected_files:
        messagebox.showwarning("Нет файлов", "Сначала выберите файлы.")
        return
    save_dir = filedialog.askdirectory(title="Выберите папку для сохранения")
    if not save_dir:
        return
    success_count = 0
    errors = []
    for path in selected_files:
        ok, error = process_file_chain(cryptcp, path, save_dir)
        if ok:
            success_count += 1
        else:
            errors.append((os.path.basename(path), error))

    # Итоговое сообщение
    if not errors:
        messagebox.showinfo("Готово", f"Все {success_count} файлов успешно обработаны.")
    else:
        error_text = "\n".join([f"{fname}: {err}" for fname, err in errors])
        messagebox.showerror("Ошибки при обработке",
                             f"Успешно: {success_count} файлов.\nОшибки:\n{error_text}")

# ======== Интерфейс ========
root = tk.Tk()
root.title("КриптоПро: ЭЦП/Расшифровка")
root.geometry("650x400")
root.resizable(False, False)

# Блок выбора файлов
frame_files = tk.LabelFrame(root, text="Выбор файлов", padx=10, pady=10)
frame_files.pack(fill="x", padx=10, pady=5)

btn_choose = tk.Button(frame_files, text="Выбрать файлы", width=20, command=choose_files, bg="#4CAF50", fg="white")
btn_choose.pack(side="left", padx=5, pady=5)

listbox_files = tk.Listbox(frame_files, width=80, height=10)
listbox_files.pack(side="left", padx=5)

# Блок действий
frame_actions = tk.LabelFrame(root, text="Действия", padx=10, pady=10)
frame_actions.pack(fill="x", padx=10, pady=5)

btn_process = tk.Button(frame_actions, text="Обработать файлы", width=25, command=process_files, bg="#2196F3", fg="white")
btn_process.pack(side="left", padx=5, pady=5)

btn_change_path = tk.Button(frame_actions, text="Указать путь к cryptcp.exe", width=25, command=change_cryptcp_path, bg="#9E9E9E", fg="white")
btn_change_path.pack(side="left", padx=5, pady=5)

# Подсказка
lbl_info = tk.Label(root, text="Выберите файлы для обработки и папку для сохранения. "
                                "Перед первым запуском программы необходимо указать путь к cryptcp.exe. В дальнейшем его можно изменить. "
                               "Для каждого файла будут выполнены расшифровка, снятие подписи и разархивирование. "
                    "Файлы внутри архивов будут сохранены в папку с таким же названием. Начальный файл будет удален.", wraplength=600, justify="left", fg="#555555")
lbl_info.pack(padx=10, pady=10)

root.mainloop()
