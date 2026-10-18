//! Static assets embedded in the binary.
//!
//! Two servers serve them — the captive portal over HTTP and the admin
//! panel over HTTPS — so the bytes live here once instead of being
//! included twice.

/// `Press Start 2P` (SIL Open Font License 1.1, see
/// `web/assets/LICENSE.press-start-2p.txt`): the pixel face used for
/// headings, which is where the offline-runner feel comes from. Body text
/// uses the system's own sans-serif, because a pixel font is unreadable
/// in sentences — and on a phone held at arm's length, unreadable is the
/// whole problem.
pub const FONT_PRESS_START_2P: &[u8] = include_bytes!("../web/assets/press-start-2p.woff2");

/// The original Chromium offline sprite sheet (BSD-3, see
/// `web/assets/LICENSE.chromium.txt`), at both densities.
pub const SPRITE_1X: &[u8] = include_bytes!("../web/assets/offline-sprite-1x.png");
pub const SPRITE_2X: &[u8] = include_bytes!("../web/assets/offline-sprite-2x.png");

/// Content types for the assets above.
pub const FONT_TYPE: &str = "font/woff2";
pub const PNG_TYPE: &str = "image/png";
