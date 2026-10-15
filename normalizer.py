from urllib.parse import unquote_plus
from html import unescape
import re
def normalize_text(text,rounds=2):
    v=text
    for _ in range(rounds):
        nv=unquote_plus(unescape(v))
        if nv==v: break
        v=nv
    v=v.replace("\\/","/")
    return re.sub(r"\s+"," ",v).strip()
