_default:
    just --list

analyze:
    uv run analyze_seeds.py --output web/data.json

serve: analyze
    python3 -m http.server 8000 -d web
