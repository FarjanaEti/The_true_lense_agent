!apt update
!apt install -y ffmpeg

!pip install yt-dlp Pillow requests ffmpeg-python


# ============================================================
# THE TRUE LENS — INGESTOR AGENT (Production Version)
# ============================================================
# This is the FIRST agent in the pipeline.
# It accepts media from ANY source, processes it safely,
# and passes a clean result to the Provenance Agent.
#
# PIPELINE:
# Input → Classify → Sanitize → Download → Detect Type
#       → Normalize → Fingerprint → JSON Output
# ============================================================

import os
import re
import json
import logging
import hashlib
import mimetypes
import tempfile
import subprocess
import requests
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

import yt_dlp
from PIL import Image

# ── LOGGING SETUP ──
# This prints what's happening at each step so you can follow along
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [INGESTOR] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger(__name__)


# ============================================================
# MODULE 1: INPUT CLASSIFIER
# Figures out what kind of input the user gave us
# ============================================================

def classify_input(user_input: str) -> str:
    """
    Looks at what the user gave and returns a label:
    - 'local_file'     → user uploaded a file from their computer
    - 'youtube_url'    → YouTube link
    - 'social_media'   → Facebook, Instagram, TikTok, Twitter
    - 'direct_media'   → a direct link ending in .mp4, .jpg, etc
    - 'hls_stream'     → a .m3u8 streaming link
    - 'unsupported'    → we can't handle this
    """
    log.info(f"Classifying input: {user_input}")

    # Check if it's a local file on disk
    if os.path.exists(user_input):
        return "local_file"

    # Check if it's a valid URL
    try:
        parsed = urlparse(user_input)
        is_url = parsed.scheme in ("http", "https")
    except:
        return "unsupported"

    if not is_url:
        return "unsupported"

    url_lower = user_input.lower()

    # YouTube
    if any(x in url_lower for x in ["youtube.com", "youtu.be"]):
        return "youtube_url"

    # Social Media
    if any(x in url_lower for x in ["facebook.com", "fb.watch", "instagram.com",
                                      "tiktok.com", "twitter.com", "x.com",
                                      "whatsapp.com"]):
        return "social_media"

    # HLS Stream
    if url_lower.endswith(".m3u8"):
        return "hls_stream"

    # Direct media file URL
    media_extensions = [".mp4", ".mov", ".avi", ".webm", ".mkv",
                        ".jpg", ".jpeg", ".png", ".webp", ".gif",
                        ".mp3", ".wav"]
    if any(url_lower.endswith(ext) for ext in media_extensions):
        return "direct_media"

    # Default — try with yt-dlp anyway (it supports 1000+ sites)
    return "social_media"


# ============================================================
# MODULE 2: SECURITY SANITIZATION
# Makes sure the input is safe before we process it
# ============================================================

DANGEROUS_EXTENSIONS = [".exe", ".bat", ".sh", ".php", ".js", ".py",
                         ".dll", ".cmd", ".vbs", ".ps1"]

MAX_FILE_SIZE_MB = 500  # reject files over 500MB

def sanitize_input(user_input: str, input_type: str) -> bool:
    """
    Returns True if input is safe, raises an error if not.
    """
    log.info("Running security checks...")

    # --- Local file checks ---
    if input_type == "local_file":
        path = Path(user_input)

        # Reject dangerous file types
        if path.suffix.lower() in DANGEROUS_EXTENSIONS:
            raise ValueError(f"BLOCKED: Dangerous file type '{path.suffix}'")

        # Reject files that are too large
        size_mb = os.path.getsize(user_input) / (1024 * 1024)
        if size_mb > MAX_FILE_SIZE_MB:
            raise ValueError(f"BLOCKED: File too large ({size_mb:.1f}MB). Max is {MAX_FILE_SIZE_MB}MB")

        log.info(f"Local file passed security checks ({size_mb:.1f}MB)")

    # --- URL checks ---
    else:
        parsed = urlparse(user_input)

        # Must be http or https
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"BLOCKED: Unsafe URL scheme '{parsed.scheme}'")

        # Block local network addresses (prevent SSRF attacks)
        blocked_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "169.254."]
        if any(b in parsed.netloc for b in blocked_hosts):
            raise ValueError("BLOCKED: Local network URLs are not allowed")

        log.info("URL passed security checks")

    return True


# ============================================================
# MODULE 3: MEDIA DOWNLOADER / EXTRACTOR
# Downloads the media from the internet to a temp folder
# ============================================================

def download_media(user_input: str, input_type: str, temp_dir: str) -> str:
    """
    Downloads media from any source to a local temp folder.
    Returns path to the downloaded file.
    For local files, just returns the original path.
    """

    # Local file — nothing to download
    if input_type == "local_file":
        log.info("Local file — skipping download step")
        return user_input

    # YouTube or Social Media — use yt-dlp
    if input_type in ("youtube_url", "social_media", "hls_stream"):
        log.info(f"Downloading via yt-dlp from: {user_input}")

        output_template = os.path.join(temp_dir, "%(title)s.%(ext)s")
        options = {
            "outtmpl": output_template,
            "format": "mp4[height<=480]/best[height<=480]/best",
            "quiet": True,
            "no_warnings": True,
        }

        with yt_dlp.YoutubeDL(options) as ydl:
            info = ydl.extract_info(user_input, download=True)
            downloaded_path = ydl.prepare_filename(info)

        log.info(f"Downloaded to: {downloaded_path}")
        return downloaded_path

    # Direct media URL — use requests to download
    if input_type == "direct_media":
        log.info(f"Downloading direct media from: {user_input}")

        response = requests.get(user_input, stream=True, timeout=30)
        response.raise_for_status()

        # Figure out file extension from URL or content-type
        ext = Path(urlparse(user_input).path).suffix or ".tmp"
        output_path = os.path.join(temp_dir, f"downloaded_media{ext}")

        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        log.info(f"Downloaded to: {output_path}")
        return output_path

    raise ValueError(f"Cannot download input type: {input_type}")


# ============================================================
# MODULE 4: MEDIA TYPE DETECTOR
# Figures out if the file is a video, image, audio, etc.
# ============================================================

def detect_media_type(file_path: str) -> str:
    """
    Detects whether the file is:
    - 'video'
    - 'image'
    - 'audio'
    - 'unsupported'
    """
    log.info(f"Detecting media type of: {file_path}")

    mime_type, _ = mimetypes.guess_type(file_path)

    if mime_type:
        if mime_type.startswith("video"):
            return "video"
        elif mime_type.startswith("image"):
            return "image"
        elif mime_type.startswith("audio"):
            return "audio"

    # Fallback — check extension manually
    ext = Path(file_path).suffix.lower()
    video_exts = [".mp4", ".mov", ".avi", ".webm", ".mkv", ".flv"]
    image_exts = [".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"]
    audio_exts = [".mp3", ".wav", ".aac", ".ogg", ".flac"]

    if ext in video_exts:
        return "video"
    elif ext in image_exts:
        return "image"
    elif ext in audio_exts:
        return "audio"

    return "unsupported"


# ============================================================
# MODULE 5: CANONICALIZATION ENGINE
# Converts media into a standard format so all agents can read it
# VIDEO  → MP4 (H.264 + AAC)
# IMAGE  → PNG
# AUDIO  → WAV
# ============================================================

def canonicalize_video(input_path: str, output_path: str) -> str:
    """Converts any video to standard MP4 format."""
    log.info("Canonicalizing video to MP4 (H.264 + AAC)...")

    result = subprocess.run([
        "ffmpeg",
        "-i", input_path,
        "-c:v", "libx264",
        "-preset", "fast",
        "-c:a", "aac",
        "-movflags", "+faststart",
        "-y",
     output_path
])

    if result.returncode != 0:
        raise RuntimeError(f"FFmpeg failed: {result.stderr}")

    log.info(f"Video saved to: {output_path}")
    return output_path


def canonicalize_image(input_path: str, output_path: str) -> str:
    """Converts any image to standard PNG format."""
    log.info("Canonicalizing image to PNG...")

    img = Image.open(input_path)
    img = img.convert("RGB")  # ensure consistent color mode
    img.save(output_path, "PNG")

    log.info(f"Image saved to: {output_path}")
    return output_path


def canonicalize_audio(input_path: str, output_path: str) -> str:
    """Converts any audio to standard WAV format."""
    log.info("Canonicalizing audio to WAV...")

    result = subprocess.run([
        "ffmpeg",
        "-i", input_path,
        "-ar", "44100",     # 44.1kHz sample rate
        "-ac", "2",         # stereo
        "-y",
        output_path
    ], capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"FFmpeg failed: {result.stderr}")

    log.info(f"Audio saved to: {output_path}")
    return output_path


def canonicalize(file_path: str, media_type: str, output_dir: str) -> tuple:
    """
    Master canonicalization function.
    Calls the right converter based on media type.
    Returns (canonical_path, canonical_format)
    """
    if media_type == "video":
        out = os.path.join(output_dir, "canonical_video.mp4")
        return canonicalize_video(file_path, out), "mp4"

    elif media_type == "image":
        out = os.path.join(output_dir, "canonical_image.png")
        return canonicalize_image(file_path, out), "png"

    elif media_type == "audio":
        out = os.path.join(output_dir, "canonical_audio.wav")
        return canonicalize_audio(file_path, out), "wav"

    else:
        raise ValueError(f"Unsupported media type: {media_type}")


# ============================================================
# MODULE 6: FINGERPRINT GENERATOR
# Creates a unique SHA-256 hash of the canonical file
# ============================================================

def generate_fingerprint(file_path: str) -> str:
    """
    Generates a SHA-256 hash of the file.
    This is the file's unique fingerprint.
    If the same video is submitted again → same hash → skip re-analysis.
    """
    log.info("Generating SHA-256 fingerprint...")

    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)

    file_hash = sha256.hexdigest()
    log.info(f"Fingerprint: {file_hash}")
    return file_hash


# ============================================================
# MAIN PIPELINE — RUN INGESTOR AGENT
# This is the function you call when a user submits media
# ============================================================

def run_ingestor_agent(user_input: str) -> dict:
    """
    MASTER FUNCTION — runs the full Ingestor Agent pipeline.

    Input:  user_input = file path OR any URL
    Output: structured JSON dict ready for the Provenance Agent
    """
    log.info("=" * 50)
    log.info("INGESTOR AGENT STARTING")
    log.info("=" * 50)

    # Create a temporary working directory for this analysis
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            # ── STEP 1: Classify input ──
            input_type = classify_input(user_input)
            log.info(f"Input classified as: {input_type}")

            if input_type == "unsupported":
                raise ValueError("Input type not supported")

            # ── STEP 2: Security check ──
            sanitize_input(user_input, input_type)

            # ── STEP 3: Download/extract media ──
            downloaded_path = download_media(user_input, input_type, temp_dir)

            # ── STEP 4: Detect media type ──
            media_type = detect_media_type(downloaded_path)
            log.info(f"Media type detected: {media_type}")

            if media_type == "unsupported":
                raise ValueError("Unsupported media type — cannot process")

           # ── STEP 5: Canonicalize ──
            output_dir = os.getcwd()

            canonical_path, canonical_format = canonicalize(
          downloaded_path,
        media_type,
        output_dir
    )

            # ── STEP 6: Fingerprint ──
            file_hash = generate_fingerprint(canonical_path)

            # ── STEP 7: Build structured output ─
            result = {
                "status": "success",
                "processed_at": datetime.now().isoformat(),
                "input_type": input_type,
                "media_type": media_type,
                "canonical_format": canonical_format,
                "file_hash": file_hash,
                "normalized_file_path": canonical_path,
                "ready_for_next_agent": True
            }

            log.info("INGESTOR AGENT COMPLETE ✓")
            log.info("Result: " + json.dumps(result, indent=2))
            return result

        except Exception as e:
            log.error(f"Ingestor Agent FAILED: {str(e)}")
            return {
                "status": "error",
                "error_message": str(e),
                "processed_at": datetime.now().isoformat(),
                "ready_for_next_agent": False
            }


# ============================================================
# TEST CASES — run this file directly to test
# ============================================================

if __name__ == "__main__":

    print("\n" + "="*60)
    print("  RUNNING INGESTOR AGENT TEST CASES")
    print("="*60)

    test_inputs = [
        # Test 1: Local video file — put your own video filename here
        "file_example_MOV_480_700kB.mov",

        # Test 2: Direct image URL
       #"https://upload.wikimedia.org/wikipedia/commons/thumb/4/47/PNG_transparency_demonstration_1.png/280px-PNG_transparency_demonstration_1.png",

        # Test 3: YouTube URL
        "https://www.youtube.com/watch?v=aqz-KE-bpKQ",
    ]

    for test_input in test_inputs:
        print(f"\n>>> Testing: {test_input}")
        result = run_ingestor_agent(test_input)
        print(f">>> Result status: {result['status']}\n")
        print(f">>> Full JSON output:")
        print(json.dumps(result, indent=2))


##################################################
# expected output of this file is:
#  RUNNING INGESTOR AGENT TEST CASES
# ============================================================

# >>> Testing: file_example_MOV_480_700kB.mov
# >>> Result status: success

# >>> Full JSON output:
# {
#   "status": "success",
#   "processed_at": "2026-05-13T07:37:01.844058",
#   "input_type": "local_file",
#   "media_type": "video",
#   "canonical_format": "mp4",
#   "file_hash": "2a095a0b805f99f236531f8dd5a4b6e7ae1414d489a8f31ca7b772488842dcb8",
#   "normalized_file_path": "/content/canonical_video.mp4",
#   "ready_for_next_agent": true
# }

# >>> Testing: https://www.youtube.com/watch?v=aqz-KE-bpKQ
# >>> Result status: success

# >>> Full JSON output:
# {
#   "status": "success",
#   "processed_at": "2026-05-13T07:39:09.110438",
#   "input_type": "youtube_url",
#   "media_type": "video",
#   "canonical_format": "mp4",
#   "file_hash": "bbe5ae33477433b1604f00ee0b0be8fefbf4a97a28d778f211dd7fa42dfb9b8d",
#   "normalized_file_path": "/content/canonical_video.mp4",
#   "ready_for_next_agent": true
# }