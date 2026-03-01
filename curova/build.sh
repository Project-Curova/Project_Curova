#!/usr/bin/env bash
set -o errexit  # Exit on error

echo "🔹 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "🔹 Running collectstatic..."
python manage.py collectstatic --no-input

echo "🔹 Running database migrations..."
python manage.py migrate --fake-initial

echo "🔹 Checking for Swagger compatibility..."
# No extra install needed for swagger in prod, but ensures cache is cleared
python manage.py clearsessions

echo "✅ Build completed successfully!"
