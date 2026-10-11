"""Second layer for Ignore-tagged groups.

IGNORE_EXPANSION   display_id of an Ignore-tagged group -> display_ids of the
                   software components it stands for by default. The engine
                   replaces the group's prerequisite row with one row per
                   component and then runs the normal flow, as if those
                   components had been named in the prerequisite file.
                   Every target must be an existing component in
                   defs/def_components.py (checked when the engine loads).
EXPANSION_NOTE     note shown when a group was expanded. {group} is the
                   group's catalog name, {products} its default products.

Hand-maintained static data.
"""

IGNORE_EXPANSION: dict[str, tuple[str, ...]] = {
    "chromium-browser": ("google-chrome", "microsoft-edge"),
    "web-browser-with-javascript-engine": ("mozilla-firefox", "google-chrome"),
    "malicious-browser-extension-installed": ("google-chrome", "microsoft-edge"),
}

EXPANSION_NOTE = (
    "{group} is a generic catalog entry. The suggestions above cover its default "
    "products, {products}; apply them to whichever of these is installed."
)
