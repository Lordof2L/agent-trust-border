from pathlib import Path
import shutil

from playwright.sync_api import sync_playwright


PROJECT = Path(__file__).resolve().parents[1]
PAGE_URL = (PROJECT / "docs" / "index.html").as_uri()
OUTPUT = PROJECT / "video" / "capture-v2"
SCREENSHOTS = OUTPUT / "screenshots"
RECORDINGS = OUTPUT / "recordings"
CHROME = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"


def settle(page, milliseconds: int = 500) -> None:
    page.wait_for_timeout(milliseconds)


def scroll_to(page, selector: str, milliseconds: int = 1200) -> None:
    page.locator(selector).scroll_into_view_if_needed()
    settle(page, milliseconds)


def capture_screenshots(browser) -> None:
    context = browser.new_context(
        viewport={"width": 1920, "height": 1080},
        device_scale_factor=1,
        color_scheme="light",
    )
    page = context.new_page()
    page.goto(PAGE_URL)
    page.wait_for_load_state("networkidle")
    settle(page, 800)

    page.screenshot(path=str(SCREENSHOTS / "01-hero.png"))
    scroll_to(page, ".metrics")
    page.screenshot(path=str(SCREENSHOTS / "02-metrics.png"))

    scroll_to(page, "#proof")
    page.screenshot(path=str(SCREENSHOTS / "03-unknown.png"))
    for index, name in ((1, "04-admit"), (2, "05-deny"), (3, "06-replay")):
        page.locator(f'.step-tab[data-step="{index}"]').click()
        settle(page, 500)
        page.screenshot(path=str(SCREENSHOTS / f"{name}.png"))

    scroll_to(page, ".architecture")
    page.screenshot(path=str(SCREENSHOTS / "07-architecture.png"))
    scroll_to(page, "#boundary")
    page.screenshot(path=str(SCREENSHOTS / "08-boundary.png"))
    context.close()


def capture_walkthrough(browser) -> Path:
    context = browser.new_context(
        viewport={"width": 1920, "height": 1080},
        device_scale_factor=1,
        color_scheme="light",
        record_video_dir=str(RECORDINGS),
        record_video_size={"width": 1920, "height": 1080},
    )
    page = context.new_page()
    page.goto(PAGE_URL)
    page.wait_for_load_state("networkidle")
    settle(page, 1800)

    for selector, pause in ((".metrics", 1800), ("#proof", 2000)):
        page.evaluate(
            "selector => document.querySelector(selector).scrollIntoView({behavior: 'smooth', block: 'start'})",
            selector,
        )
        settle(page, pause)

    for index in (1, 2, 3):
        page.locator(f'.step-tab[data-step="{index}"]').click()
        settle(page, 2400)

    for selector, pause in ((".architecture", 2200), ("#boundary", 2600)):
        page.evaluate(
            "selector => document.querySelector(selector).scrollIntoView({behavior: 'smooth', block: 'start'})",
            selector,
        )
        settle(page, pause)

    recorded = page.video
    context.close()
    path = Path(recorded.path())
    destination = OUTPUT / "viewer-walkthrough.webm"
    shutil.move(path, destination)
    return destination


def main() -> None:
    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    RECORDINGS.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, executable_path=CHROME)
        capture_screenshots(browser)
        walkthrough = capture_walkthrough(browser)
        browser.close()
    print(f"captured {len(list(SCREENSHOTS.glob('*.png')))} screenshots")
    print(f"captured {walkthrough}")


if __name__ == "__main__":
    main()
