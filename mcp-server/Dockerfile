FROM node:lts

RUN useradd -ms /bin/bash app

COPY --chown=app:app . /home/app/

USER app
WORKDIR /home/app/

RUN npm install
RUN npm run build

CMD ["node", "build/index.js"]
