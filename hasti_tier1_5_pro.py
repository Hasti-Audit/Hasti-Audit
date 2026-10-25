import re
import math

def evaluate_hasti_pro(query: str):
    """
    Parses Tier 1.5 Pro Persian financial and advanced math queries using regex.
    Returns the computed numeric result or "NO_MATCH" if the safety guard triggers.
    """
    q = query.strip()
    
    # P01: Future Value
    m = re.match(r"^ارزش آتی مبلغ اولیه\s+([\d\.]+)\s+با نرخ سود\s+([\d\.]+)\s+درصد در مدت\s+([\d\.]+)\s+سال چند است؟$", q)
    if m:
        A, B, C = float(m.group(1)), float(m.group(2)), float(m.group(3))
        return round(A * ((1 + B / 100) ** C), 2)

    # P02: Simple Interest
    m = re.match(r"^سود ساده برای اصل پول\s+([\d\.]+)\s+با نرخ\s+([\d\.]+)\s+درصد و مدت\s+([\d\.]+)\s+سال چقدر است؟$", q)
    if m:
        A, B, C = float(m.group(1)), float(m.group(2)), float(m.group(3))
        return round(A * (B / 100) * C, 2)

    # P03: Percentage Growth Rate
    m = re.match(r"^تغییر درصدی از مقدار\s+([\d\.]+)\s+به مقدار\s+([\d\.]+)\s+چند درصد است؟$", q)
    if m:
        A, B = float(m.group(1)), float(m.group(2))
        if A == 0: return "NO_MATCH"
        return round(((B - A) / A) * 100, 2)

    # P04: Modulo Arithmetic
    m = re.match(r"^باقی‌مانده تقسیم عدد\s+([\d\.]+)\s+بر عدد\s+([\d\.]+)\s+چند است؟$", q)
    if m:
        A, B = float(m.group(1)), float(m.group(2))
        if B == 0: return "NO_MATCH"
        return A % B

    # P05: Profit Margin
    m = re.match(r"^حاشیه سود با درآمد کل\s+([\d\.]+)\s+و بهای تمام شده\s+([\d\.]+)\s+چند درصد است؟$", q)
    if m:
        A, B = float(m.group(1)), float(m.group(2))
        if A == 0: return "NO_MATCH"
        return round(((A - B) / A) * 100, 2)

    # P06: Weighted Average
    m = re.match(r"^میانگین وزنی دو عدد\s+([\d\.]+)\s+با وزن\s+([\d\.]+)\s+و\s+([\d\.]+)\s+با وزن\s+([\d\.]+)\s+چند است؟$", q)
    if m:
        A, W1, B, W2 = float(m.group(1)), float(m.group(2)), float(m.group(3)), float(m.group(4))
        if (W1 + W2) == 0: return "NO_MATCH"
        return round((A * W1 + B * W2) / (W1 + W2), 2)

    # P07: Discount Percentage
    m = re.match(r"^درصد تخفیف برای قیمت اصلی\s+([\d\.]+)\s+و قیمت پرداختی\s+([\d\.]+)\s+چند است؟$", q)
    if m:
        A, B = float(m.group(1)), float(m.group(2))
        if A == 0: return "NO_MATCH"
        return round(((A - B) / A) * 100, 2)

    # P08: Present Value
    m = re.match(r"^ارزش فعلی مبلغ آینده\s+([\d\.]+)\s+با نرخ تنزیل\s+([\d\.]+)\s+درصد در مدت\s+([\d\.]+)\s+سال چند است؟$", q)
    if m:
        A, B, C = float(m.group(1)), float(m.group(2)), float(m.group(3))
        return round(A / ((1 + B / 100) ** C), 2)

    # P09: Standard Deviation (3 items)
    m = re.match(r"^انحراف معیار اعداد\s+([\d\.]+)\s+و\s+([\d\.]+)\s+و\s+([\d\.]+)\s+چند است؟$", q)
    if m:
        vals = [float(m.group(1)), float(m.group(2)), float(m.group(3))]
        mean = sum(vals) / len(vals)
        variance = sum((x - mean) ** 2 for x in vals) / len(vals)
        return round(math.sqrt(variance), 2)

    # P10: Z-Score
    m = re.match(r"^نمره استاندارد برای مقدار\s+([\d\.]+)\s+با میانگین\s+([\d\.]+)\s+و انحراف معیار\s+([\d\.]+)\s+چند است؟$", q)
    if m:
        A, B, C = float(m.group(1)), float(m.group(2)), float(m.group(3))
        if C == 0: return "NO_MATCH"
        return round((A - B) / C, 2)

    # Safety Guard
    return "NO_MATCH"
