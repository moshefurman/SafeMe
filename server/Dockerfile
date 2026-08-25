# ─────────────────────────────────────────────────────────────
#  SafeMe API
#
#  Node 24 מפשיט טיפוסים מ-TypeScript באופן מובנה, ולכן אין שלב
#  בנייה: הקוד רץ ישירות מהמקור. פחות חלקים נעים בשרשרת הפריסה.
# ─────────────────────────────────────────────────────────────

FROM node:24-alpine AS deps

WORKDIR /app
COPY package.json package-lock.json ./

# ci ולא install: נועל בדיוק את הגרסאות מהקובץ, בלי הפתעות בפריסה
RUN npm ci --omit=dev


FROM node:24-alpine

WORKDIR /app

ENV NODE_ENV=production
# בקונטיינר חובה להאזין לכל הממשקים. ברירת המחדל בקוד היא לולאה
# מקומית, שהיא הנכונה לפיתוח ובלתי נגישה מבחוץ.
ENV HOST=0.0.0.0
ENV PORT=3000

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY migrations ./migrations
COPY scripts ./scripts

# הרצה כמשתמש לא מורשה. התהליך אינו זקוק לשורש לשום דבר.
USER node

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/v1/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "src/server.ts"]
