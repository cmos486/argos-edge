// GeoFlag renders a flag emoji from an ISO-3166-1 alpha-2 country
// code using the Unicode regional indicator symbol pair (U+1F1E6..FF).
// No external icon library: the browser's emoji font handles it.
//
// Private IPs and unknown countries render a neutral glyph instead
// of a flag so the UI never shows a misleading country for LAN or
// unresolved addresses.
interface Props {
  countryCode?: string;
  isPrivate?: boolean;
  className?: string;
}

export default function GeoFlag({ countryCode, isPrivate, className }: Props) {
  const cls = className ?? 'inline-block';
  if (isPrivate) {
    return (
      <span className={cls} title="Private / LAN address">
        🏠
      </span>
    );
  }
  if (!countryCode || countryCode.length !== 2) {
    return (
      <span className={cls} title="Unknown location">
        🌐
      </span>
    );
  }
  const cc = countryCode.toUpperCase();
  const flag = String.fromCodePoint(
    0x1f1e6 + cc.charCodeAt(0) - 0x41,
    0x1f1e6 + cc.charCodeAt(1) - 0x41,
  );
  return (
    <span className={cls} title={cc}>
      {flag}
    </span>
  );
}
