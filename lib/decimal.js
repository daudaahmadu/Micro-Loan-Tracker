const Decimal = require("decimal.js");

Decimal.set({ precision: 80, rounding: Decimal.ROUND_HALF_UP });
const MAX_SCALE = 4;

function decimalString(value, { positive = false, max = null, allowZero = true } = {}) {
    if (typeof value !== "string" && typeof value !== "number") return null;
    const text = String(value).trim();
    if (!/^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(text)) return null;
    const scale = text.includes(".") ? text.length - text.indexOf(".") - 1 : 0;
    if (scale > MAX_SCALE) return null;
    let decimal;
    try { decimal = new Decimal(text); } catch { return null; }
    if (!allowZero && decimal.isZero()) return null;
    if (positive && decimal.isNegative()) return null;
    if (max !== null && decimal.gt(max)) return null;
    return decimal.toFixed(scale);
}

function canonicalDecimalString(value) {
    if (typeof value !== "string" && typeof value !== "number") return null;
    const text = String(value).trim();
    if (!/^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(text)) return null;
    try {
        return new Decimal(text).toString();
    } catch {
        return null;
    }
}

function money(value) { return new Decimal(String(value || 0)); }
function add(...values) { return values.reduce((total, value) => total.plus(money(value)), new Decimal(0)).toString(); }
function subtract(left, right) { return money(left).minus(money(right)).toString(); }
function multiply(left, right) { return money(left).times(money(right)).toString(); }
function divide(left, right) { return money(left).div(money(right)).toString(); }
function nonNegative(value) { return money(value).lt(0) ? "0" : money(value).toString(); }
function formatNgn(value) {
    const fixed = money(value).toFixed(2);
    const [whole, fraction] = fixed.split(".");
    const grouped = whole.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    return fraction === "00" ? grouped : `${grouped}.${fraction}`;
}

module.exports = { Decimal, MAX_SCALE, decimalString, canonicalDecimalString, money, add, subtract, multiply, divide, nonNegative, formatNgn };
