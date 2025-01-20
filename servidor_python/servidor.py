import socket
import struct
import threading
import tkinter as tk
from tkinter import filedialog, ttk
import telnetlib
from tkinter import colorchooser

# Constantes
VERSION_ID = 9
VERSION_MAJOR = 6
VERSION_MINOR = 23
VERSION_PATCH = 0
REQUEST_CONNECTION = 0x01
ACK = 0x01
NACK = 0x00
KEEPALIVE_INTERVAL = 5  # Intervalo em segundos para envio de KeepAlive
highlight_rules = {}  # Armazena palavras-chave e suas cores


# Variáveis globais
telnet_connection = None  # Conexão Telnet
default_syslog_port = 514  # Porta padrão do servidor Syslog
syslog_server_running = False
syslog_server_socket = None

# Interface gráfica
root = tk.Tk()
root.title("Servidor Syslog")
root.geometry("800x950")  # Alterado de 800x900 para 800x950
root.configure(bg="#f0f0f0")

# Variáveis globais relacionadas a logs
show_iris_logs = tk.BooleanVar(value=True)
show_syslog_logs = tk.BooleanVar(value=True)
log_filter = tk.StringVar(value="All")

# Funções gerais
def update_iris_logs(message):
    if show_iris_logs.get():
        iris_text.insert(tk.END, message + "\n")
        iris_text.see(tk.END)

def update_syslog_logs(message):
    if show_syslog_logs.get():
        syslog_text.insert(tk.END, message + "\n")
        syslog_text.see(tk.END)
        for keyword, color in highlight_rules.items():
            if keyword in message:
                start_index = syslog_text.search(keyword, "1.0", tk.END)
                while start_index:
                    end_index = f"{start_index}+{len(keyword)}c"
                    # Adiciona a tag e configura a cor
                    syslog_text.tag_add(keyword, start_index, end_index)
                    syslog_text.tag_config(keyword, foreground=color)
                    start_index = syslog_text.search(keyword, end_index, tk.END)


def clear_iris_logs():
    iris_text.delete("1.0", tk.END)

def clear_syslog_logs():
    syslog_text.delete("1.0", tk.END)

# Funções relacionadas ao IRIS
def start_iris():
    global telnet_connection
    try:
        telnet_host = telnet_host_entry.get()
        telnet_port = int(telnet_port_entry.get())
        telnet_user = telnet_user_entry.get()
        telnet_password = telnet_password_entry.get()
        destination_ip = destination_ip_entry.get()  # Novo: obter o IP do destino

        update_iris_logs("Conectando ao Telnet...")
        telnet_connection = telnetlib.Telnet(telnet_host, telnet_port)

        # Enviar credenciais
        telnet_connection.read_until(b"login: ")
        telnet_connection.write(telnet_user.encode("ascii") + b"\n")
        telnet_connection.read_until(b"Password: ")
        telnet_connection.write(telnet_password.encode("ascii") + b"\n")

        update_iris_logs("Login Telnet bem-sucedido.")

        # Executar comando IRIS com o IP de destino
        command = f"/mnt/flash/firmware/iris -d {destination_ip}\n"
        telnet_connection.write(command.encode("ascii"))
        update_iris_logs(f"Comando IRIS enviado: {command.strip()}")

        # Ler saída do IRIS
        threading.Thread(target=read_iris_logs, daemon=True).start()

    except Exception as e:
        update_iris_logs(f"Erro ao conectar via Telnet: {e}")


def stop_iris():
    global telnet_connection
    if telnet_connection is None:
        update_iris_logs("O IRIS não está em execução.")
        return

    try:
        telnet_connection.close()
        telnet_connection = None
        update_iris_logs("Conexão Telnet encerrada e IRIS parado.")
    except Exception as e:
        update_iris_logs(f"Erro ao encerrar IRIS: {e}")

def read_iris_logs():
    global telnet_connection
    if telnet_connection is None:
        return

    try:
        while True:
            output = telnet_connection.read_very_eager().decode("ascii")
            if output:
                update_iris_logs(output.strip())
    except Exception as e:
        update_iris_logs(f"Erro ao ler logs do IRIS: {e}")

# Funções de log
def save_iris_log():
    log_content = iris_text.get("1.0", tk.END).strip()
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if file_path:
        with open(file_path, "w") as file:
            file.write(log_content)
        update_iris_logs(f"Log do IRIS salvo em: {file_path}")

def save_syslog_log():
    log_content = syslog_text.get("1.0", tk.END).strip()
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if file_path:
        with open(file_path, "w") as file:
            file.write(log_content)
        update_syslog_logs(f"Log do Syslog salvo em: {file_path}")

# Funções relacionadas ao Syslog
def start_syslog_server_thread():
    global syslog_server_running
    if not syslog_server_running:
        port = int(syslog_port_entry.get())
        syslog_server_running = True
        threading.Thread(target=start_syslog_server, args=("0.0.0.0", port), daemon=True).start()
        update_syslog_logs("Servidor Syslog iniciado.")
    else:
        update_syslog_logs("Servidor Syslog já está em execução.")

def stop_syslog_server():
    global syslog_server_running, syslog_server_socket
    if syslog_server_running:
        syslog_server_running = False
        if syslog_server_socket:
            syslog_server_socket.close()
            syslog_server_socket = None
        update_syslog_logs("Servidor Syslog parado.")
    else:
        update_syslog_logs("Servidor Syslog não está em execução.")

def start_syslog_server(host="0.0.0.0", port=1514):
    global syslog_server_socket
    syslog_server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    syslog_server_socket.bind((host, port))
    update_syslog_logs(f"Iniciando servidor Syslog em {host}:{port}...")
    try:
        while syslog_server_running:
            data, address = syslog_server_socket.recvfrom(1024)
            message = data.decode().strip()
            update_syslog_logs(f"Mensagem recebida de {address}: {message}")
    except Exception as e:
        if syslog_server_running:
            update_syslog_logs(f"Erro no servidor Syslog: {e}")
    finally:
        syslog_server_socket.close()

# Abas
notebook = ttk.Notebook(root)
notebook.pack(fill="both", expand=True, padx=10, pady=10)

# Aba IRIS
frame_iris_tab = tk.Frame(notebook, bg="#f0f0f0")
notebook.add(frame_iris_tab, text="IRIS")

# Controles do IRIS
frame_iris_controls = tk.Frame(frame_iris_tab, bg="#f0f0f0")
frame_iris_controls.pack(pady=20)

# Adicionar um campo para o IP do destino na aba IRIS
frame_destination_config = tk.Frame(frame_iris_tab, bg="#f0f0f0")
frame_destination_config.pack(pady=10, fill="x")

destination_ip_label = tk.Label(frame_destination_config, text="IP de Destino:", font=("Arial", 12), fg="#333", bg="#f0f0f0")
destination_ip_label.pack(side="left", padx=5)

destination_ip_entry = tk.Entry(frame_destination_config, font=("Arial", 12), width=15)
destination_ip_entry.insert(0, "10.3.9.93")  # Valor padrão
destination_ip_entry.pack(side="left", padx=5)


start_iris_button = tk.Button(frame_iris_controls, text="Iniciar IRIS", command=start_iris, font=("Arial", 12), bg="#4CAF50", fg="white", width=15)
start_iris_button.pack(side="left", padx=10)

stop_iris_button = tk.Button(frame_iris_controls, text="Parar IRIS", command=stop_iris, font=("Arial", 12), bg="#f44336", fg="white", width=15)
stop_iris_button.pack(side="left", padx=10)

clear_iris_button = tk.Button(frame_iris_controls, text="Limpar Logs IRIS", command=clear_iris_logs, font=("Arial", 12), bg="#2196F3", fg="white", width=15)
clear_iris_button.pack(side="left", padx=10)

save_iris_button = tk.Button(frame_iris_controls, text="Salvar Logs IRIS", command=save_iris_log, font=("Arial", 12), bg="#FFC107", fg="black", width=15)
save_iris_button.pack(side="left", padx=10)

# Configurações do Telnet
frame_telnet_config = tk.Frame(frame_iris_tab, bg="#f0f0f0")
frame_telnet_config.pack(pady=10, fill="x")

host_label = tk.Label(frame_telnet_config, text="IP da Placa:", font=("Arial", 12), fg="#333", bg="#f0f0f0")
host_label.pack(side="left", padx=5)
telnet_host_entry = tk.Entry(frame_telnet_config, font=("Arial", 12), width=15)
telnet_host_entry.insert(0, "10.3.111.179")
telnet_host_entry.pack(side="left", padx=5)

port_label = tk.Label(frame_telnet_config, text="Porta:", font=("Arial", 12), fg="#333", bg="#f0f0f0")
port_label.pack(side="left", padx=5)
telnet_port_entry = tk.Entry(frame_telnet_config, font=("Arial", 12), width=5)
telnet_port_entry.insert(0, "23")
telnet_port_entry.pack(side="left", padx=5)

user_label = tk.Label(frame_telnet_config, text="Usuário:", font=("Arial", 12), fg="#333", bg="#f0f0f0")
user_label.pack(side="left", padx=5)
telnet_user_entry = tk.Entry(frame_telnet_config, font=("Arial", 12), width=10)
telnet_user_entry.insert(0, "root")
telnet_user_entry.pack(side="left", padx=5)

password_label = tk.Label(frame_telnet_config, text="Senha:", font=("Arial", 12), fg="#333", bg="#f0f0f0")
password_label.pack(side="left", padx=5)
telnet_password_entry = tk.Entry(frame_telnet_config, font=("Arial", 12), width=10, show="*")
telnet_password_entry.insert(0, "digicon")
telnet_password_entry.pack(side="left", padx=5)

# Logs do IRIS
frame_iris_logs = tk.Frame(frame_iris_tab, bg="#f0f0f0")
frame_iris_logs.pack(padx=10, pady=10, fill="both", expand=True)

iris_text = tk.Text(frame_iris_logs, font=("Courier", 10), bg="#1e1e1e", fg="white", height=20)
iris_text.pack(padx=10, pady=10, fill="both", expand=True)

# Aba Syslog
frame_syslog_tab = tk.Frame(notebook, bg="#f0f0f0")
notebook.add(frame_syslog_tab, text="Syslog")

frame_syslog_controls = tk.Frame(frame_syslog_tab, bg="#f0f0f0")
frame_syslog_controls.pack(pady=20)

# Exibir IP do servidor
server_ip = socket.gethostbyname(socket.gethostname())
server_ip_label = tk.Label(frame_syslog_controls, text=f"IP do Servidor: {server_ip}", font=("Arial", 12), bg="#f0f0f0")
server_ip_label.pack(side="left", padx=10)

syslog_port_label = tk.Label(frame_syslog_controls, text="Porta do Syslog:", font=("Arial", 12), bg="#f0f0f0")
syslog_port_label.pack(side="left", padx=5)
syslog_port_entry = tk.Entry(frame_syslog_controls, font=("Arial", 12), width=10)
syslog_port_entry.insert(0, str(default_syslog_port))
syslog_port_entry.pack(side="left", padx=5)

start_syslog_button = tk.Button(frame_syslog_controls, text="Iniciar Syslog", command=start_syslog_server_thread, font=("Arial", 12), bg="#4CAF50", fg="white")
start_syslog_button.pack(side="left", padx=10)

stop_syslog_button = tk.Button(frame_syslog_controls, text="Parar Syslog", command=stop_syslog_server, font=("Arial", 12), bg="#f44336", fg="white")
stop_syslog_button.pack(side="left", padx=10)

clear_syslog_button = tk.Button(frame_syslog_controls, text="Limpar Logs Syslog", command=clear_syslog_logs, font=("Arial", 12), bg="#2196F3", fg="white", width=15)
clear_syslog_button.pack(side="left", padx=10)

save_syslog_button = tk.Button(frame_syslog_controls, text="Salvar Logs Syslog", command=save_syslog_log, font=("Arial", 12), bg="#FFC107", fg="black", width=15)
save_syslog_button.pack(side="left", padx=10)

# Logs do Syslog
frame_syslog_logs = tk.Frame(frame_syslog_tab, bg="#f0f0f0")
frame_syslog_logs.pack(padx=10, pady=10, fill="both", expand=True)

syslog_text = tk.Text(frame_syslog_logs, font=("Courier", 10), bg="#1e1e1e", fg="white", height=20)
syslog_text.pack(padx=10, pady=10, fill="both", expand=True)

# Filtros de Logs
frame_filters = tk.Frame(frame_syslog_tab, bg="#f0f0f0")
frame_filters.pack(pady=10)

filter_label = tk.Label(frame_filters, text="Filtro de Logs:", font=("Arial", 12), bg="#f0f0f0")
filter_label.pack(side="left", padx=5)

filter_entry = tk.Entry(frame_filters, font=("Arial", 12), textvariable=log_filter, width=15)
filter_entry.pack(side="left", padx=5)

# Função para selecionar cor
def select_filter_color():
    color_code = colorchooser.askcolor(title="Escolha uma cor para o filtro")[1]
    if color_code:
        highlight_rules[log_filter.get()] = color_code
        update_syslog_logs(f"Cor {color_code} associada ao filtro: {log_filter.get()}")

# Botão para selecionar cor
color_button = tk.Button(frame_filters, text="Escolher Cor", command=select_filter_color, font=("Arial", 12), bg="#FFC107", fg="black")
color_button.pack(side="left", padx=5)


# Início da interface
root.mainloop()
