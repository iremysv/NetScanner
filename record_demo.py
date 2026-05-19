import asyncio
from playwright.async_api import async_playwright
import imageio
import os
import time
from PIL import Image

async def capture_frames():
    frames = []
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1200, "height": 800})
        page = await context.new_page()
        
        async def snap(wait=0.2):
            await asyncio.sleep(wait)
            screenshot_bytes = await page.screenshot()
            frames.append(screenshot_bytes)

        # 1. Dashboard ana sayfa
        await page.goto("http://127.0.0.1:8000")
        await page.wait_for_selector("#terminal-output")
        for _ in range(5): await snap(0.5)
        
        # 2. Nmap Tab'ına tıkla
        await page.click('li[data-section="nmap"]')
        for _ in range(3): await snap(0.2)
        
        # 3. Nmap formunu doldur ve başlat
        await page.fill('#target-ip', '127.0.0.1')
        await snap(0.5)
        await page.click('#btn-scan')
        for _ in range(5): await snap(0.5)
        
        # 4. Canlı izleme sekmesine geç
        await page.click('li[data-section="live"]')
        for _ in range(3): await snap(0.2)
        
        # 5. Canlı izlemeyi başlat
        await page.click('#btn-start-sniff')
        for _ in range(5): await snap(0.5)
        
        # 6. Canlı izlemeyi durdur
        await page.click('#btn-stop-sniff')
        for _ in range(5): await snap(0.5)

        await browser.close()
    return frames

def create_gif():
    frames = asyncio.run(capture_frames())
    
    print(f"Toplam {len(frames)} frame yakalandı, GIF oluşturuluyor...")
    
    os.makedirs("Demo", exist_ok=True)
    
    # Save frames as temporary files to read into ImageIO
    images = []
    for i, frame_bytes in enumerate(frames):
        img_path = f"Demo/temp_{i}.png"
        with open(img_path, "wb") as f:
            f.write(frame_bytes)
        img = Image.open(img_path)
        img.thumbnail((800, 600))  # Resize to keep file size small
        images.append(img)
    
    # Save as GIF
    gif_path = "Demo/netscanner_demo.gif"
    images[0].save(
        gif_path,
        save_all=True,
        append_images=images[1:],
        duration=200, # 200ms per frame
        loop=0
    )
    
    # Cleanup temp files
    for i in range(len(frames)):
        os.remove(f"Demo/temp_{i}.png")
        
    print(f"GIF başarıyla oluşturuldu: {gif_path}")

if __name__ == "__main__":
    create_gif()
