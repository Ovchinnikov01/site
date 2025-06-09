FROM python:3.9

RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
RUN apt-get install -y nodejs

WORKDIR /app

COPY package*.json postcss.config.js tailwind.config.js ./
COPY requirements.txt ./

RUN pip install --no-cache-dir -r requirements.txt

RUN npm install
RUN npm run build-css  # Собираем Tailwind

COPY . .

CMD ["gunicorn", "app:app", "-b", "0.0.0.0:8000"]