#!/bin/bash


set -e

echo "🔥 Starting Devlin Pentesting Automation Tool..."

if [ ! -f "settings.example.json" ]; then
    echo "❌ Error: Please run this script from the Devlin root directory"
    exit 1
fi

if [ ! -f "settings.json" ]; then
    echo "📝 Creating settings.json from template..."
    cp settings.example.json settings.json
    echo "⚠️  Please configure your API keys in settings.json"
fi

mkdir -p data/scans
mkdir -p data/reports
mkdir -p data/loot

echo "🚀 Starting FastAPI backend..."
cd backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload &
BACKEND_PID=$!
cd ..

sleep 3

echo "🌐 Starting React frontend..."
cd frontend
npm run dev -- --host 0.0.0.0 --port 5000 &
FRONTEND_PID=$!
cd ..

echo "✅ Devlin is starting up..."
echo "🔗 Frontend: http://localhost:5000"
echo "🔗 Backend API: http://localhost:8000"
echo "📚 API Docs: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop all services"

trap "echo '🛑 Shutting down...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" INT
wait
