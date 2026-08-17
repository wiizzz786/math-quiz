self.__scramjet$config = {
  prefix: '/scramjet/service/',
  codec: self.__scramjet$codecs ? self.__scramjet$codecs.xor : null,
  config: '/scramjet/scramjet.config.js',
  serviceWorker: '/scramjet/scramjet.worker.js',
  bundle: '/scramjet/scramjet.all.js',
  wisp: (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/wisp/',
};
