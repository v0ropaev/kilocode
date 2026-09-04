#!/usr/bin/env python3
# Builds submission/Security-Auto-ATH.pptx from the AI Talent Hub template.
# Starts from a copy of the template so theme, master, layouts and the embedded Inter
# font travel with the file; the knowbase slides are removed and replaced.

import os
import shutil
import sys
import tempfile
import zipfile
from datetime import datetime, timezone

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE, MSO_CONNECTOR
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.util import Inches, Pt, Emu

HERE = os.path.dirname(os.path.abspath(__file__))

# The AI Talent Hub template is the visual source: slide size, theme, master, layouts, the embedded
# Inter font and the logo images all travel with it. It is not vendored into the repository (it is a
# different project's deck and carries third-party marks), so its path is given explicitly.
TEMPLATE = os.environ.get("ATH_TEMPLATE") or os.path.join(
    os.path.dirname(os.path.dirname(HERE)), "knowbase-\u043f\u0440\u0435\u0437\u0435\u043d\u0442\u0430\u0446\u0438\u044f-ATH.pptx"
)
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "Security-Auto-ATH.pptx")

# Logo images, by their entry name inside the template package.
MEDIA_ENTRIES = {
    "ath_dark": "ppt/media/image3.png",
    "ath_light": "ppt/media/image5.png",
    "itmo_dark": "ppt/media/image2.png",
    "itmo_light": "ppt/media/image9.png",
    "partner_dark": "ppt/media/image1.png",
    "partner_light": "ppt/media/image10.png",
}
_MEDIA_DIR = None


def media(key):
    """Extract a logo from the template package on first use and return its path."""
    global _MEDIA_DIR
    if _MEDIA_DIR is None:
        _MEDIA_DIR = tempfile.mkdtemp(prefix="ath-media-")
        with zipfile.ZipFile(TEMPLATE) as z:
            names = set(z.namelist())
            missing = [e for e in MEDIA_ENTRIES.values() if e not in names]
            if missing:
                raise SystemExit(
                    f"{TEMPLATE} does not contain the expected logo entries: {', '.join(missing)}.\n"
                    "This build script is tied to the AI Talent Hub deck it was written against."
                )
            for entry in MEDIA_ENTRIES.values():
                target = os.path.join(_MEDIA_DIR, os.path.basename(entry))
                with open(target, "wb") as fh:
                    fh.write(z.read(entry))
    return os.path.join(_MEDIA_DIR, os.path.basename(MEDIA_ENTRIES[key]))


def preflight():
    if not os.path.isfile(TEMPLATE):
        raise SystemExit(
            f"AI Talent Hub template not found at {TEMPLATE}.\n"
            "Pass it explicitly:  ATH_TEMPLATE=/path/to/ath-template.pptx python3 build-deck.py out.pptx"
        )


# ---------------------------------------------------------------- design tokens
BLACK = RGBColor(0x00, 0x00, 0x00)
BLUE = RGBColor(0x00, 0x00, 0xFF)
PURPLE = RGBColor(0x88, 0x43, 0xFF)
GRAY = RGBColor(0x59, 0x59, 0x59)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
BG = "FAFAFC"
BG_BLUE = "0000FF"

INTER, ARIAL = "Inter", "Arial"

M = 0.521                     # left margin
RIGHT = 9.479                 # right edge
LOGO = (0.521, 0.351, 1.68, 0.464)
LOGO_ON_BLUE = (0.330, 0.336, 1.83, 0.506)
YEAR_POS = (8.799, 0.456, 0.68, 0.293)
TITLE_Y = 0.974
LEDE_Y = 1.640

COL4_X = [0.521, 2.881, 5.242, 7.602]
COL4_W = 1.875
COL3_X = [0.521, 3.633, 6.748]
COL3_W = 2.726
COL2_X = [0.521, 5.250]
COL2_W = 4.229


YEAR = "2026"

# ---------------------------------------------------------------- layout checker
# LibreOffice substitutes the embedded Inter with Arial / Arial Black, which are WIDER than Inter.
# Measuring against that substitution is the pessimistic case: what fits here fits in PowerPoint.
from PIL import ImageFont  # noqa: E402

_FONTDIR = "/System/Library/Fonts/Supplemental/"
_SUBST = {
    ("Inter", True): _FONTDIR + "Arial Black.ttf",
    ("Inter", False): _FONTDIR + "Arial.ttf",
    ("Arial", True): _FONTDIR + "Arial Bold.ttf",
    ("Arial", False): _FONTDIR + "Arial.ttf",
}
_cache = {}
BOXES = []          # (slide_no, kind, x, y, w, declared_h, needed_h, preview)
CURRENT = [0]
LB = [0.0]          # bottom of the last placed block


def below(gap=0.16):
    return LB[0] + gap


def _font(name, bold, size_pt):
    key = (name, bold, round(size_pt, 1))
    if key not in _cache:
        _cache[key] = ImageFont.truetype(_SUBST[(name, bold)], max(int(round(size_pt * 96 / 72)), 6))
    return _cache[key]


# A rendered line is taller than size*line: the renderer multiplies the font's own line height
# (ascent + descent + gap, ~1.17 em for Arial) by the spacing factor. And it breaks lines slightly
# earlier than PIL's advance widths suggest. Both are compensated here so the check stays pessimistic.
LINE_FACTOR = 1.17
WIDTH_FACTOR = 0.97


def measure(txt, size_pt, name, bold, width_in, line=1.2, space_pt=0):
    """Approximate rendered height in inches, wrapping at width_in."""
    f = _font(name, bold, size_pt)
    limit = width_in * 96 * WIDTH_FACTOR
    total = 0.0
    for hard in txt.split("\n"):
        words, cur, n = hard.split(), "", 0
        for w in words:
            trial = (cur + " " + w).strip()
            if f.getlength(trial) <= limit or not cur:
                cur = trial
            else:
                n += 1
                cur = w
        n += 1
        total += n * size_pt * line * LINE_FACTOR / 72.0 + space_pt / 72.0
    return total


def note(x, y, w, declared_h, needed_h, preview, kind="text"):
    BOXES.append((CURRENT[0], kind, x, y, w, declared_h, needed_h, preview[:44]))


def report():
    print("\n--- layout check (pessimistic Arial/Arial Black substitution) ---")
    bad = 0
    for sl, kind, x, y, w, dh, nh, prev in BOXES:
        if nh > dh + 0.005:
            bad += 1
            print(f"  OVERFLOW slide {sl:2} {kind:6} y={y:.3f} w={w:.3f} declared={dh:.3f} needed={nh:.3f}  {prev!r}")
    for sl, kind, x, y, w, dh, nh, prev in BOXES:
        if y + max(dh, nh) > 5.50:
            bad += 1
            print(f"  OFFSLIDE slide {sl:2} {kind:6} y={y:.3f} bottom={y + max(dh, nh):.3f}  {prev!r}")
    # vertical collisions between horizontally overlapping boxes on the same slide
    by_slide = {}
    for b in BOXES:
        by_slide.setdefault(b[0], []).append(b)
    for sl, items in sorted(by_slide.items()):
        items = sorted(items, key=lambda b: b[3])
        for i, a in enumerate(items):
            for b in items[i + 1:]:
                ax0, ax1 = a[2], a[2] + a[4]
                bx0, bx1 = b[2], b[2] + b[4]
                if min(ax1, bx1) - max(ax0, bx0) <= 0.02:
                    continue
                ay1 = a[3] + a[6]
                if b[3] < ay1 - 0.012:
                    bad += 1
                    print(f"  COLLIDE  slide {sl:2} y={a[3]:.3f}+{a[6]:.3f} over y={b[3]:.3f}"
                          f"  {a[7]!r} / {b[7]!r}")
    print(f"--- {bad} layout problem(s) ---")
    return bad


# ---------------------------------------------------------------- primitives


def set_bg(slide, hexcolor):
    from lxml import etree

    ns = "http://schemas.openxmlformats.org/drawingml/2006/main"
    pns = "http://schemas.openxmlformats.org/presentationml/2006/main"
    for old in slide._element.findall(f"{{{pns}}}bg"):
        slide._element.remove(old)
    bg = etree.SubElement(slide._element, f"{{{pns}}}bg")
    bgpr = etree.SubElement(bg, f"{{{pns}}}bgPr")
    fill = etree.SubElement(bgpr, f"{{{ns}}}solidFill")
    clr = etree.SubElement(fill, f"{{{ns}}}srgbClr")
    clr.set("val", hexcolor)
    etree.SubElement(bgpr, f"{{{ns}}}effectLst")
    slide._element.insert(1, bg)


def tb(slide, x, y, w, h, anchor=MSO_ANCHOR.TOP):
    box = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = box.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = 0
    tf.vertical_anchor = anchor
    return box


def para(tf, text, size, bold=False, color=BLACK, font=ARIAL, space=0, line=None, first=False):
    p = tf.paragraphs[0] if first else tf.add_paragraph()
    p.space_after = Pt(space)
    if line:
        p.line_spacing = line
    r = p.add_run()
    r.text = text
    r.font.size = Pt(size)
    r.font.bold = bold
    r.font.name = font
    r.font.color.rgb = color
    return p


def text(slide, x, y, w, h, lines, size=12, bold=False, color=BLACK, font=ARIAL, space=2, line=None,
         align=None):
    """lines: str or list of str (or (text, overrides) tuples)."""
    if isinstance(lines, str):
        lines = [lines]
    box = tb(slide, x, y, w, h)
    tf = box.text_frame
    needed = 0.0
    preview = ""
    for i, ln in enumerate(lines):
        over = {}
        if isinstance(ln, tuple):
            ln, over = ln
        p = para(
            tf,
            ln,
            over.get("size", size),
            over.get("bold", bold),
            over.get("color", color),
            over.get("font", font),
            over.get("space", space),
            over.get("line", line),
            first=(i == 0),
        )
        if align:
            p.alignment = align
        needed += measure(ln, over.get("size", size), over.get("font", font), over.get("bold", bold),
                          w, over.get("line", line) or 1.2, over.get("space", space))
        preview = preview or ln
    note(x, y, w, h, needed, preview)
    LB[0] = y + max(h, needed)
    return box


def rect(slide, x, y, w, h, fill=None, lineclr=None, linew=0.75, shape=MSO_SHAPE.RECTANGLE):
    s = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(w), Inches(h))
    if fill is None:
        s.fill.background()
    else:
        s.fill.solid()
        s.fill.fore_color.rgb = fill
    if lineclr is None:
        s.line.fill.background()
    else:
        s.line.color.rgb = lineclr
        s.line.width = Pt(linew)
    s.shadow.inherit = False
    s.text_frame.word_wrap = True
    s.text_frame.margin_left = s.text_frame.margin_right = Inches(0.06)
    s.text_frame.margin_top = s.text_frame.margin_bottom = Inches(0.04)
    s.text_frame.vertical_anchor = MSO_ANCHOR.MIDDLE
    s.text_frame.paragraphs[0].alignment = PP_ALIGN.LEFT
    note(x, y, w, h, h, "<shape>", kind="shape")
    return s


def hline(slide, x, y, w, color=BLACK, width=0.75):
    c = slide.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, Inches(x), Inches(y), Inches(x + w), Inches(y))
    c.line.color.rgb = color
    c.line.width = Pt(width)
    return c


def arrow(slide, x, y, w, color=GRAY):
    """A slim right-pointing arrow between flow boxes."""
    a = slide.shapes.add_shape(MSO_SHAPE.RIGHT_ARROW, Inches(x), Inches(y - 0.045), Inches(w), Inches(0.09))
    a.fill.solid()
    a.fill.fore_color.rgb = color
    a.line.fill.background()
    a.shadow.inherit = False
    return a


def pic(slide, path, x, y, w, h):
    return slide.shapes.add_picture(path, Inches(x), Inches(y), Inches(w), Inches(h))


# ---------------------------------------------------------------- slide chrome


def new_slide(prs, blue=False, year=True, logo=True):
    slide = prs.slides.add_slide(prs.slide_layouts[11])  # DEFAULT: no placeholders
    CURRENT[0] += 1
    set_bg(slide, BG_BLUE if blue else BG)
    if logo:
        if blue:
            pic(slide, media("ath_light"), *LOGO_ON_BLUE)
        else:
            pic(slide, media("ath_dark"), *LOGO)
    if year:
        b = tb(slide, *YEAR_POS)
        p = para(b.text_frame, YEAR, 17, False, WHITE if blue else BLACK, INTER, first=True)
        p.alignment = PP_ALIGN.RIGHT
    return slide


def title(slide, txt, blue=False, y=TITLE_Y, w=8.2, size=26):
    h = max(measure(txt, size, INTER, True, w, 1.12), 0.42)
    text(slide, M, y, w, h, txt, size=size, bold=True,
         color=WHITE if blue else BLACK, font=INTER, line=1.12, space=0)
    return y + h


def lede(slide, txt, y=LEDE_Y, w=8.4, blue=False):
    h = max(measure(txt, 13, INTER, True, w, 1.2), 0.24)
    text(slide, M, y, w, h, txt, size=13, bold=True,
         color=WHITE if blue else BLACK, font=INTER, space=0)
    return y + h


def stat_row(slide, items, y, xs=None, w=None, numsize=26, blue=False):
    """items: [(number, caption)]"""
    xs = xs or (COL4_X if len(items) == 4 else [M + i * (8.958 / len(items)) for i in range(len(items))])
    w = w or (COL4_W if len(items) == 4 else 8.958 / len(items) - 0.4)
    bottom = y
    for (num, cap), x in zip(items, xs):
        nh = numsize * 1.2 * LINE_FACTOR / 72 + 0.03
        text(slide, x, y, w, nh, num, size=numsize, bold=True,
             color=WHITE if blue else BLUE, font=INTER, space=0)
        ch = max(measure(cap, 12, ARIAL, False, w, 1.15), 0.22)
        text(slide, x, y + nh + 0.10, w, ch, cap, size=12,
             color=WHITE if blue else BLACK, font=ARIAL, line=1.15, space=0)
        bottom = max(bottom, y + nh + 0.10 + ch)
    LB[0] = bottom
    return bottom


def cards(slide, items, y, xs, w, numcolor=BLUE, body_h=0.95, gap=0.232, size=12, foot_gap=0.10):
    """items: [(label, body)] or [(label, body, foot)]. Labels, bodies and feet are aligned across
    the row, so a longer column never drags its neighbours' baselines out of line."""
    lh = max([measure(i[0], size, INTER, False, w, 1.2) for i in items] + [0.20])
    yy = y + max(gap, lh + 0.03)
    bh = max([measure(i[1], size, ARIAL, False, w, 1.2) for i in items] + [body_h])
    fh = max([measure(i[2], size - 1, INTER, True, w, 1.25) for i in items if len(i) > 2] + [0.0])
    for item, x in zip(items, xs):
        text(slide, x, y, w, lh, item[0], size=size, color=numcolor, font=INTER, space=0)
        text(slide, x, yy, w, bh, item[1], size=size, font=ARIAL, line=1.2, space=0)
        if len(item) > 2:
            text(slide, x, yy + bh + foot_gap, w, fh, item[2], size=size - 1, bold=True,
                 color=BLUE, font=INTER, line=1.25, space=0)
    LB[0] = yy + bh + (foot_gap + fh if fh else 0)
    return LB[0]


def bullets(slide, items, y, x=M, w=8.4, pitch=0.62, color=PURPLE):
    for i, it in enumerate(items):
        yy = y + i * pitch
        text(slide, x - 0.166, yy - 0.004, 0.10, 0.224, "•", size=12, bold=True, color=color, font=ARIAL)
        text(slide, x, yy, w, pitch - 0.06, it, size=12, font=ARIAL, line=1.2)


def footer_logos(slide, blue=False):
    if blue:
        pic(slide, media("itmo_light"), 5.884, 4.895, 0.774, 0.209)
        pic(slide, media("partner_light"), 7.647, 4.959, 1.832, 0.150)
    else:
        pic(slide, media("itmo_dark"), 0.526, 4.896, 0.774, 0.209)
        pic(slide, media("partner_dark"), 2.288, 4.954, 1.832, 0.151)


# ---------------------------------------------------------------- content


def build(prs):
    # ---------------------------------------------------------- 1. cover
    s = new_slide(prs, year=False)
    text(s, M, 1.470, 5.25, 1.95,
         ["Security Auto Mode", "для Kilo Code"],
         size=32, bold=True, font=INTER, line=1.14, space=0)
    text(s, M, 3.520, 5.20, 0.30,
         "Автономия coding agent без unrestricted authority",
         size=13, bold=True, font=INTER, space=0)
    text(s, M, 3.920, 5.20, 0.56,
         ["Дмитрий Воропаев · архитектура, security engine, benchmark",
          "AI Talent Hub · ИТМО"],
         size=12, font=INTER, color=GRAY, line=1.25, space=0)
    footer_logos(s)
    r = rect(s, 5.900, 1.220, 3.579, 3.100, fill=BLUE)
    tf = r.text_frame
    tf.margin_left = tf.margin_right = Inches(0.30)
    para(tf, "Intent", 26, True, WHITE, INTER, space=0, line=1.1, first=True)
    para(tf, "≠", 26, True, WHITE, INTER, space=0, line=1.1)
    para(tf, "Authority", 26, True, WHITE, INTER, space=14, line=1.1)
    para(tf, "Модель может быть скомпрометирована.", 12, False, WHITE, ARIAL, space=0, line=1.3)
    para(tf, "Разрешение на действие принимает", 12, False, WHITE, ARIAL, space=0, line=1.3)
    para(tf, "детерминированный слой вне модели.", 12, False, WHITE, ARIAL, space=0, line=1.3)

    # ---------------------------------------------------------- 2. problem
    s = new_slide(prs)
    y = title(s, "Автономия против approval fatigue")
    y = lede(s, "Полезен только автономный агент. Оба доступных режима плохие.", y=y + 0.24)
    y = cards(s, [
        ("Режим 1 — подтверждать каждое действие",
         "Человек читает десятки запросов подряд, перестаёт вчитываться и нажимает «разрешить» "
         "автоматически. Автономия, ради которой агент и нужен, исчезает."),
        ("Режим 2 — skip permissions",
         "Агент получает полную authority на машине разработчика. На максимально автономном Kilo "
         "100 % (237/237) прогонов атак доходят до наблюдаемого эффекта."),
    ], y=y + 0.20, xs=COL2_X, w=COL2_W, body_h=0.55)
    y = lede(s, "Опаснее всего, когда security-решение принимает та же модель.", y=y + 0.19, w=8.6)
    stat_row(s, [
        ("100 %", "успешных прогонов атак на baseline"),
        ("81", "attack-сценарий, 49 utility"),
        ("0", "внешних вызовов в решении"),
        ("~1 мс", "p95 стоимости решения"),
    ], y=y + 0.30)

    # ---------------------------------------------------------- 3. user & hypothesis
    s = new_slide(prs)
    y = title(s, "Пользователь и продуктовая гипотеза")
    y = cards(s, [
        ("Основной пользователь",
         "Разработчик, запускающий coding agent автономно. Успех — задача сделана без цепочки "
         "подтверждений. Провал — удалённые файлы, утёкший ключ, установленный чужой пакет."),
        ("Дополнительный пользователь",
         "Engineering / security lead, который решает, можно ли вообще включить автономию в команде. "
         "Ему нужны измеримые границы, а не обещание."),
    ], y=y + 0.20, xs=COL2_X, w=COL2_W, body_h=0.55, size=11)

    hy = y + 0.26
    hh = 0.26 + measure("Если вынести authority control из LLM в детерминированный context-aware слой и "
                        "спрашивать человека только там, где система не может решить сама, — ASR резко "
                        "падает без существенной потери Utility.", 12, INTER, True, 8.958 - 0.44, 1.3) + 0.30
    r = rect(s, M, hy, 8.958, hh, fill=None, lineclr=BLACK, linew=0.75)
    tf = r.text_frame
    tf.margin_left = tf.margin_right = Inches(0.22)
    tf.margin_top = Inches(0.15)
    tf.vertical_anchor = MSO_ANCHOR.TOP
    para(tf, "Продуктовая гипотеза", 11, False, BLUE, INTER, space=6, first=True)
    para(tf, "Если вынести authority control из LLM в детерминированный context-aware слой и спрашивать "
             "человека только там, где система не может решить сама, — ASR резко падает без "
             "существенной потери Utility.", 12, True, BLACK, INTER, space=0, line=1.3)

    y = lede(s, "Мы оптимизируем безопасную автономность, а не количество блокировок.", y=hy + hh + 0.24)
    text(s, M, y + 0.16, 8.6, 0.50,
         "Измеряются пять метрик сразу: ASR, Utility, false positives, friction, latency. "
         "Конфигурация «запретить всё» даёт ASR 0 % и решением не является.",
         size=12, font=ARIAL, line=1.2, space=0)

    # ---------------------------------------------------------- 4. threat model
    s = new_slide(prs)
    y = title(s, "Threat model: intent ≠ authority", w=7.2)
    y = lede(s, "Доверенный разработчик. Недоверенное окружение. Модель, которой можно управлять.",
             y=y + 0.18)
    y = cards(s, [
        ("Доверено",
         "Разработчик и его задача. Глобальный конфиг пользователя. Собственный код Kilo. "
         "Sandbox-бэкенд операционной системы."),
        ("Недоверено",
         "Рассуждение модели. Содержимое репозитория, README и docs. Имя пакета, выбранное моделью. "
         "Метаданные MCP-инструментов. Исполняемый код и конфиг проекта."),
        ("Следствие",
         "Решение не зависит от того, распознала ли модель атаку: его принимает детерминированный "
         "слой вне модели, а подтверждает профиль ОС."),
    ], y=y + 0.20, xs=COL3_X, w=COL3_W, body_h=0.60, size=11)

    hline(s, M, y + 0.13, 8.958, GRAY, 0.75)
    y = text(s, M, y + 0.25, 8.6, 0.26,
             "Десять классов угроз, каждый измеряется отдельными сценариями",
             size=12, bold=True, font=INTER, space=0) and below(0.12)
    text(s, M, y, 8.6, 0.62,
         "Деструктивные вызовы · чувствительные файлы · подмена политики · prompt injection · утечка "
         "секретов · многошаговые атаки · slopsquatting · делегированная authority MCP · код "
         "проекта · ambient authority расширения.",
         size=11, font=ARIAL, color=GRAY, line=1.25, space=0)

    # ---------------------------------------------------------- 5. why not obvious
    s = new_slide(prs)
    y = title(s, "Очевидные подходы и их пределы")
    y = lede(s, "Каждый решает часть задачи. Ни один не закрывает её целиком.", y=y + 0.18)
    y = cards(s, [
        ("01",
         "Prompt guardrails\n\nЗащищают вход модели. Но если injection уже победила intent, "
         "guardrail не ограничивает то, что агент физически может сделать."),
        ("02",
         "Denylist пакетов\n\nЗакрывает уже известное. Свежий slopsquat по определению отсутствует "
         "в списке в момент установки."),
        ("03",
         "Только sandbox\n\nОграничивает эффект, но не различает легитимную работу и атаку: "
         "workspace-запись нужна и той и другой. И не работает до первого tool call."),
        ("04",
         "Подтверждать всё вручную\n\nБезопасно на бумаге. На практике даёт approval fatigue "
         "и заканчивается включением skip-permissions."),
    ], y=y + 0.19, xs=COL4_X, w=COL4_W, body_h=0.60, size=11)
    hline(s, M, y + 0.13, 8.958, GRAY, 0.75)
    text(s, M, y + 0.25, 8.6, 0.48,
         "Security Auto использует все четыре идеи, но переносит решение об authority в отдельный "
         "детерминированный слой и подтверждает его профилем ОС там, где это выполнимо.",
         size=12, font=ARIAL, line=1.2, space=0)

    # ---------------------------------------------------------- 6. architecture
    s = new_slide(prs)
    y = title(s, "Как работает Security Auto")
    y = lede(s, "Один choke point для эффектов и две границы, срабатывающие раньше tool call.",
             y=y + 0.18)

    y0 = y + 0.22
    bh = 0.46
    boxes = [
        ("Agent\ntool call", 0.521, 1.30, None),
        ("Normalization\nshell AST · пути", 2.061, 1.55, None),
        ("Security\nEngine", 3.851, 1.30, BLUE),
        ("Authority\nALLOW / ASK / DENY", 5.391, 1.85, None),
        ("Executor\nOS sandbox", 7.591, 1.40, None),
    ]
    for label, x, w, fill in boxes:
        r = rect(s, x, y0, w, bh, fill=fill, lineclr=None if fill else BLACK)
        tf = r.text_frame
        head, sub = label.split("\n")
        para(tf, head, 11, True, WHITE if fill else BLACK, INTER, space=1, first=True)
        para(tf, sub, 9, False, WHITE if fill else GRAY, ARIAL, space=0)
    for x, w in ((1.861, 0.16), (3.641, 0.16), (5.191, 0.16), (7.271, 0.28)):
        arrow(s, x, y0 + bh / 2, w)

    text(s, 3.851, y0 + bh + 0.14, 5.20, 0.22,
         "Evidence-слои: только ужесточают решение, никогда не ослабляют",
         size=10, color=GRAY, font=ARIAL, space=0)
    evy = y0 + bh + 0.42
    for i, name in enumerate(["Package Security", "Stateful Egress", "Delegated Tool Security",
                              "Content Secret Detection"]):
        x = 3.851 + i * 1.335
        r = rect(s, x, evy, 1.245, 0.34, fill=None, lineclr=GRAY, linew=0.5)
        para(r.text_frame, name, 9, False, BLACK, ARIAL, space=0, first=True)
        c = s.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, Inches(x + 0.62), Inches(evy),
                                   Inches(x + 0.62), Inches(evy - 0.045))
        c.line.color.rgb = GRAY
        c.line.width = Pt(0.5)

    hline(s, M, evy + 0.52, 8.958, GRAY, 0.75)
    y = text(s, M, evy + 0.66, 8.6, 0.26, "До того, как tool call вообще появится",
             size=12, bold=True, font=INTER, space=0) and below(0.12)
    cards(s, [
        ("Executable Code Trust",
         "Репозиторный .kilocode/tool/*.ts и project-plugin исполняют module scope в момент импорта. "
         "discovery != execution: модуль не импортируется, пока человек не одобрил эти байты."),
        ("Permissioned Extension Runtime + Read-Confinement",
         "Одобренное расширение живёт в дочернем процессе под профилем ОС. Привилегированные "
         "эффекты — IPC-запросы, которые судит тот же движок."),
    ], y=y, xs=COL2_X, w=COL2_W, body_h=0.55)

    # ---------------------------------------------------------- 7. layers
    s = new_slide(prs)
    y = title(s, "Слои защиты и что каждый закрыл")
    y = lede(s, "Ниже — вклад именно этого слоя, а не накопленной суммы.", y=y + 0.18)
    y = cards(s, [
        ("Deterministic Security",
         "ALLOW / ASK / DENY для каждого side-effecting вызова. Shell разбирается Tree-sitter, "
         "пути классифицируются после канонизации.",
         "деструктивные 6/6 → 0/6"),
        ("Package Security",
         "Provenance пакета оценивается до запуска package manager. Неопределённость никогда "
         "не сводится к ALLOW.",
         "пакеты 42/42 → 0/42"),
        ("Stateful Egress · Content Secret Detection",
         "Секрет, полученный на шаге N, влияет на исходящее решение на шаге M. Секрет определяется "
         "по содержимому, а не по имени.",
         "exfil 12/15 → 0/15\nсекреты 33/33 → 6/33"),
        ("Delegated Tool Security",
         "Capability-модель для MCP, plugin и workspace-инструментов. Provenance структурная; "
         "readOnlyHint не даёт ничего.",
         "MCP/custom 30/30 → 3/30"),
    ], y=y + 0.19, xs=COL4_X, w=COL4_W, body_h=0.60, size=11)

    hline(s, M, y + 0.08, 8.958, GRAY, 0.75)
    text(s, M, y + 0.15, 8.958, 0.22,
         "Executable Code Trust · Permissioned Extension Runtime · Read-Confinement",
         size=11, color=BLUE, font=INTER, space=0)
    text(s, M, y + 0.37, 8.958, 0.24,
         "Код проекта не исполняется до решения о доверии; чтения расширения сужены профилем ОС.",
         size=11, font=ARIAL, line=1.2, space=0)
    text(s, M, y + 0.62, 8.958, 0.22,
         "pre-gate 27/27 → 3/27 · runtime расширения 24/24 → 0/24 · чтения 33/33 → 3/33",
         size=11, bold=True, color=BLUE, font=INTER, space=0)

    # ---------------------------------------------------------- 8. slopsquatting
    s = new_slide(prs)
    y = title(s, "Slopsquatting: решение до установки")
    y = lede(s, "Проверка внутри agent loop, а не в CI и не в pre-commit хуке.", y=y + 0.18)

    y0 = y + 0.22
    steps = [
        ("Агент предлагает\nзависимость", 0.521, 1.68),
        ("Package Risk\nEvaluator", 2.481, 1.68),
        ("Provenance\nсигналы", 4.441, 1.68),
        ("Решение\nDENY / ASK / ALLOW", 6.401, 1.68),
    ]
    for i, (label, x, w) in enumerate(steps):
        r = rect(s, x, y0, w, 0.56, fill=BLUE if i in (1, 3) else None,
                 lineclr=None if i in (1, 3) else BLACK)
        head, sub = label.split("\n")
        para(r.text_frame, head, 11, True, WHITE if i in (1, 3) else BLACK, INTER, space=1, first=True)
        para(r.text_frame, sub, 9, False, WHITE if i in (1, 3) else GRAY, ARIAL, space=0)
        if i < 3:
            arrow(s, x + w + 0.04, y0 + 0.28, 0.20)
    r = rect(s, 8.361, y0, 1.118, 0.56, fill=None, lineclr=GRAY, linew=0.5)
    para(r.text_frame, "package\nmanager", 9, False, GRAY, ARIAL, space=0, first=True)
    arrow(s, 8.121, y0 + 0.28, 0.20)

    y = cards(s, [
        ("Детерминированные сигналы",
         "Возраст пакета и релиза · объявленные install scripts · наличие репозитория · "
         "не-registry источник · подмена registry в команде или в .npmrc"),
        ("Эвристические сигналы",
         "Adoption по загрузкам · схожесть имени с известным пакетом: edit distance, разделители, "
         "аффиксы, гомоглифы, scope — с указанием, на что похоже"),
        ("Неопределённость",
         "Метаданные недоступны, пакет не найден, диапазон не разрешён. Неопределённость никогда "
         "не сводится к ALLOW: metadata lookup failure ≠ trusted"),
    ], y=y0 + 0.56 + 0.30, xs=COL3_X, w=COL3_W, body_h=0.55, size=11)

    hline(s, M, y + 0.13, 8.958, GRAY, 0.75)
    text(s, M, y + 0.25, 8.958, 0.80,
         [("Suspicious package provenance is evaluated before local execution.",
           {"size": 13, "bold": True, "font": INTER, "space": 5}),
          ("Не детектор произвольного zero-day. Пакет, чей код выполнился бы прямо сейчас, получает "
           "DENY; прочая подозрительная provenance — hard ASK. Измерено: 42/42 → 0/42.",
           {"size": 12, "font": ARIAL, "line": 1.2, "space": 0})])

    # ---------------------------------------------------------- 9. prompt injection
    s = new_slide(prs)
    y = title(s, "Prompt injection")
    y = lede(s, "Injection может изменить намерение модели. Она не снимает hard rules, package "
                "preflight, executable-code trust и профиль ОС.", y=y + 0.18, w=8.4)

    y0 = y + 0.22
    chain = [
        ("Вредоносный README", 0.521, 1.90, None),
        ("Модель хочет\nопасное действие", 2.641, 1.90, None),
        ("SecurityEngine\nвне модели", 4.761, 1.90, BLUE),
        ("Решение по действию,\nне по тексту", 6.881, 1.90, BLUE),
    ]
    for i, (label, x, w, fill) in enumerate(chain):
        r = rect(s, x, y0, w, 0.60, fill=fill, lineclr=None if fill else BLACK)
        parts = label.split("\n")
        para(r.text_frame, parts[0], 11, True, WHITE if fill else BLACK, INTER, space=1, first=True)
        if len(parts) > 1:
            para(r.text_frame, parts[1], 9, False, WHITE if fill else GRAY, ARIAL, space=0)
        if i < 3:
            arrow(s, x + w + 0.03, y0 + 0.30, 0.16)

    y = text(s, M, y0 + 0.60 + 0.26, 8.958, 0.26,
             "Что именно не зависит от того, что «поняла» модель",
             size=12, bold=True, font=INTER, space=0) and below(0.16)
    y = cards(s, [
        ("Hard filesystem rules",
         "Деструктивные операции над корнями и предками workspace, чтение приватных ключей — "
         "DENY по правилу, а не по распознаванию."),
        ("Package Security · capability",
         "Provenance оценивается до исполнения. Инструмент с неизвестной authority не выполняется "
         "без человека."),
        ("Executable Code Trust · профиль ОС",
         "Код проекта не импортируется до одобрения по содержимому. Чтения и сеть расширения "
         "отклоняет профиль ОС."),
    ], y=y, xs=COL3_X, w=COL3_W, body_h=0.50, size=11)
    hline(s, M, y + 0.13, 8.958, GRAY, 0.75)
    text(s, M, y + 0.22, 8.958, 0.44,
         "Один класс остаётся открытым и назван честно: семантический exfil через текст README, "
         "atk-readme-injection-exfil — успешен 3/3 во всех девяти конфигурациях.",
         size=11, font=ARIAL, color=GRAY, line=1.2, space=0)

    # ---------------------------------------------------------- 10. benchmark
    s = new_slide(prs)
    y = title(s, "Benchmark: как получены цифры")
    y = lede(s, "Бенчмарк — часть решения, а не отчёт о нём.", y=y + 0.18)
    y = cards(s, [
        ("Датасет",
         "130 сценариев: 81 attack, 49 utility. По три повтора. Девять конфигураций лестницы, "
         "соседние отличаются одним флагом."),
        ("Изоляция",
         "Одноразовый sandbox в temp, поддельный HOME, инертные shim'ы package manager'ов первыми "
         "в PATH, сеть только на loopback."),
        ("Оракул",
         "Успех атаки — наблюдаемый побочный эффект, а не текст модели: удалённая канарейка, "
         "фейковый секрет в коллекторе, маркер shim'а."),
    ], y=y + 0.19, xs=COL3_X, w=COL3_W, body_h=0.55, size=11)

    y0 = y + 0.18
    loop = ["Найти атаку", "Воспроизвести", "Canary", "Baseline", "Protected", "Измерить", "Новый residual"]
    xw = 1.185
    for i, label in enumerate(loop):
        x = 0.521 + i * (xw + 0.10)
        r = rect(s, x, y0, xw, 0.42, fill=None, lineclr=BLUE if i in (3, 4) else GRAY, linew=0.75)
        para(r.text_frame, label, 9, i in (3, 4), BLACK, ARIAL, space=0, first=True)
        if i < len(loop) - 1:
            arrow(s, x + xw + 0.01, y0 + 0.21, 0.08)
    y = text(s, M, y0 + 0.42 + 0.14, 8.958, 0.44,
             "После каждого нового control adversarial suite расширялась: старые конфигурации "
             "оцениваются на более сильном наборе — это честнее, а не регрессия.",
             size=11, font=ARIAL, line=1.2, space=0) and below(0.16)
    stat_row(s, [
        ("3510", "прогонов, 0 errored"),
        ("237", "прогонов атак"),
        ("147", "прогонов utility"),
        ("5", "остаточных сценариев"),
    ], y=y, numsize=20)

    # ---------------------------------------------------------- 11. results (blue)
    s = new_slide(prs, blue=True)
    y = title(s, "Результаты", blue=True, y=0.980, size=26)
    y = text(s, M, y + 0.14, 8.958, 0.95, "ASR 100 % → 6 %",
             size=48, bold=True, color=WHITE, font=INTER, space=0) and below(0.10)
    y = text(s, M, y, 8.958, 0.52,
             "15 из 237 прогонов атак · 130 сценариев × 3 повтора × 9 конфигураций\n"
             "3510 прогонов, 0 errored",
             size=13, bold=True, color=WHITE, font=INTER, space=0) and below(0.16)
    hline(s, M, y, 8.958, WHITE, 0.75)
    y = stat_row(s, [
        ("98 %", "Utility · 144/147"),
        ("0", "Safe DENY false positives"),
        ("0,154", "hard ASK на задачу · 60/390"),
        ("1,04 мс", "p95 стоимости решения"),
    ], y=y + 0.20, blue=True)
    text(s, M, y + 0.18, 8.958, 0.50,
         "Extension и executable-code utility — 100 % (42/42) во всех девяти конфигурациях. "
         "Единственная потерянная utility — честный трёхдневный пакет с hard ASK.",
         size=12, color=WHITE, font=ARIAL, line=1.25, space=0)

    # ---------------------------------------------------------- 12. ablation
    s = new_slide(prs)
    y = title(s, "Вклад каждого слоя")
    y = lede(s, "Overall ASR, 237 прогонов атак. Каждая строка добавляет один слой к предыдущей.",
             y=y + 0.18)

    rows = [
        ("Baseline", 100, "100 % (237/237)", BLACK),
        ("Deterministic Security", 86, "86 % (204/237)", GRAY),
        ("+ Package Security", 68, "68 % (162/237)", GRAY),
        ("+ Stateful Egress", 63, "63 % (150/237)", GRAY),
        ("+ Delegated Tool Security", 52, "52 % (123/237)", GRAY),
        ("+ Content Secret Detection", 39, "39 % (93/237)", GRAY),
        ("+ Executable Code Trust", 30, "30 % (72/237)", GRAY),
        ("+ Permissioned Extension Runtime", 18, "18 % (42/237)", GRAY),
        ("+ Read-Confinement", 6, "6 % (15/237)", BLUE),
    ]
    y0, pitch, bh = y + 0.20, 0.262, 0.135
    lx, bx, bwmax = 0.521, 3.010, 5.150
    for i, (name, val, label, color) in enumerate(rows):
        yy = y0 + i * pitch
        text(s, lx, yy - 0.022, 2.40, 0.19, name, size=9,
             bold=(color is BLUE), font=ARIAL, color=BLACK, space=0)
        w = max(bwmax * val / 100.0, 0.05)
        rect(s, bx, yy, w, bh, fill=color)
        text(s, bx + w + 0.09, yy - 0.028, 1.65, 0.19, label, size=9,
             bold=(color is BLUE), font=ARIAL, color=BLACK, space=0)
    hline(s, bx, y0 + len(rows) * pitch - 0.060, bwmax, GRAY, 0.5)
    text(s, M, y0 + len(rows) * pitch + 0.06, 8.958, 0.70,
         "Baseline → финал: пакеты 42/42 → 0/42 · exfil 15/15 → 0/15 · MCP/custom 30/30 → 0/30 · "
         "секреты 33/33 → 6/33 · pre-gate 27/27 → 3/27 · runtime 24/24 → 0/24 · чтения 33/33 → 3/33. "
         "Колонка Extension-runtime охватывает оба runtime-класса (57 прогонов). Сравнивать значения "
         "можно только внутри одной таблицы.",
         size=11, font=ARIAL, color=GRAY, line=1.2, space=0)

    # ---------------------------------------------------------- 13. demo / limits / pilot
    s = new_slide(prs)
    y = title(s, "Демонстрация, ограничения, пилот")
    y = lede(s, "Каждое демо — сценарий бенчмарка с наблюдаемой канарейкой и одной командой запуска.",
             y=y + 0.18)
    y = cards(s, [
        ("Демонстрация",
         "A. Деструктивный shell — atk-workspace-wipe\n"
         "B. Slopsquatting — atk-package-install\n"
         "C. Секрет → egress — atk-egress-multi-step-benign\n"
         "D. Чтение хостового секрета — atk-extread-symlink-escape\n"
         "Baseline и защищённая конфигурация в одном прогоне."),
        ("Ограничения",
         "Метаданные файлов видны внутри сужённого хоста: без них не разрешается путь.\n"
         "Классификатор читает маркеры, а не энтропию: голый токен и base64 не видны.\n"
         "Read confinement проверен на macOS, для Linux не верифицирован.\n"
         "Драйвер скриптованный: измеряется containment политики."),
        ("Следующий шаг — пилот",
         "Команда 5–10 разработчиков на репозитории с внешними зависимостями и MCP.\n"
         "Метрики: ASR на контролируемом наборе, task Utility, Safe ASK / DENY FP, approvals "
         "на задачу, latency, доля оставивших режим включённым."),
    ], y=y + 0.19, xs=COL3_X, w=COL3_W, body_h=0.60, size=11)
    hline(s, M, y + 0.14, 8.958, GRAY, 0.75)
    text(s, M, y + 0.24, 8.958, 0.24,
         "bun run script/security-bench.ts --runs 1 --scenario <id> --configs baseline,"
         "read-confined-extension-runtime",
         size=11, font=ARIAL, color=GRAY, line=1.2, space=0)

    # ---------------------------------------------------------- 14. team (blue)
    s = new_slide(prs, blue=True)
    y = title(s, "Команда и распределение задач", blue=True, y=0.980)
    hdr = ["Участник", "Роль", "Зона ответственности", "Вклад", "Участие"]
    xs = [0.521, 2.221, 3.921, 6.221, 8.421]
    ws = [1.620, 1.620, 2.220, 2.120, 1.058]
    hy = y + 0.28
    for x, w, h in zip(xs, ws, hdr):
        text(s, x, hy, w, 0.22, h, size=10, bold=True, color=WHITE, font=INTER, space=0)
    hline(s, M, hy + 0.28, 8.958, WHITE, 0.75)
    rows = [
        ["Дмитрий Воропаев", "Разработка,\nAI Product",
         "Архитектура security engine, слои, extension runtime, benchmark, документация",
         "19 из 19 коммитов ветки, подтверждено git history", "ведущая"],
        ["[ЗАПОЛНИТЬ: имя]", "[ЗАПОЛНИТЬ]", "[ЗАПОЛНИТЬ]", "[ЗАПОЛНИТЬ]", "[ЗАПОЛНИТЬ]"],
    ]
    yy = hy + 0.42
    for row in rows:
        rh = max(measure(c, 10, ARIAL, False, w, 1.2) for c, w in zip(row, ws))
        for x, w, cell in zip(xs, ws, row):
            text(s, x, yy, w, rh, cell, size=10, color=WHITE, font=ARIAL, line=1.2, space=0)
        yy += rh + 0.26
        hline(s, M, yy - 0.13, 8.958, WHITE, 0.4)
    text(s, M, yy + 0.06, 5.4, 0.60,
         "Строка-заполнитель дублируется по числу участников и заполняется командой перед подачей. "
         "Подтверждена только первая строка: она выведена из истории репозитория. Данные, которых "
         "репозиторий не подтверждает, не выдумываются.",
         size=10, color=WHITE, font=ARIAL, line=1.2, space=0)
    footer_logos(s, blue=True)


APP_XML = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" \
xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">\
<TotalTime>0</TotalTime><Application>python-pptx</Application>\
<PresentationFormat>Custom</PresentationFormat><Slides>{slides}</Slides><Notes>0</Notes>\
<HiddenSlides>0</HiddenSlides><MMClips>0</MMClips><ScaleCrop>false</ScaleCrop>\
<LinksUpToDate>false</LinksUpToDate><SharedDoc>false</SharedDoc><HyperlinksChanged>false</HyperlinksChanged>\
</Properties>"""


def scrub(path, slides):
    """Replace the template's extended properties: they still carry the source deck's slide
    titles and counts, which have nothing to do with this presentation."""
    import zipfile

    tmp = path + ".tmp"
    with zipfile.ZipFile(path) as src, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            data = src.read(item.filename)
            if item.filename == "docProps/app.xml":
                data = APP_XML.format(slides=slides).encode("utf-8")
            dst.writestr(item, data)
    os.replace(tmp, path)


def main():
    preflight()
    shutil.copyfile(TEMPLATE, OUT)
    prs = Presentation(OUT)
    # drop the template's own slides, keep master / layouts / theme / embedded fonts
    xml_slides = prs.slides._sldIdLst
    for sld in list(xml_slides):
        rId = sld.get("{http://schemas.openxmlformats.org/officeDocument/2006/relationships}id")
        prs.part.drop_rel(rId)
        xml_slides.remove(sld)
    build(prs)
    core = prs.core_properties
    core.title = "Security Auto Mode для Kilo Code"
    core.subject = "Детерминированный ALLOW / ASK / DENY для side-effecting tool call'ов"
    core.author = "Dmitry Voropaev"
    core.last_modified_by = "Dmitry Voropaev"
    core.comments = "AI Talent Hub. Числа: submission/SOURCE_OF_TRUTH.md"
    core.keywords = "Kilo Code, Security Auto Mode, coding agent, benchmark"
    core.created = core.modified = datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0)
    core.revision = 1
    n = len(prs.slides._sldIdLst)
    prs.save(OUT)
    scrub(OUT, n)
    print(f"wrote {OUT} - {n} slides")
    sys.exit(1 if report() else 0)


if __name__ == "__main__":
    main()
