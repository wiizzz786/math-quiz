/**
 * Resolve address bar input to a full URL (Mercury Scramjet-App behavior).
 * @param {string} input
 * @param {string} template Search template with %s placeholder
 */
export function search(input, template) {
  try {
    return new URL(input).toString();
  } catch {
    /* not absolute */
  }
  try {
    const url = new URL(`http://${input}`);
    if (url.hostname.includes(".")) return url.toString();
  } catch {
    /* not host-like */
  }
  return template.replace("%s", encodeURIComponent(input));
}
