# netcode.io-typescript

TypeScript/JavaScript implementation of [netcode.io](http://netcode.io).

### Why did I create TypeScript/JavaScript version of netcode?

JavsScript is mainly used for webs, I know we cannot send UDP packets from the browser ([Why can't I send UDP packets from a browser?](http://gafferongames.com/post/why_cant_i_send_udp_packets_from_a_browser/)) . These days, instant games (e.g. Facebook Instant games) are quite popular, and face-paced multiplayer games are inevitable on these platforms. These platforms are using typical web technologies, but mostly they also expose UDP APIs from the native side. So this is the reason that I want a JavaScript version of netcode mainly for the client-side.

### netcode version

1.0.1

### build project

npm run-script build

### Testing

mocha tests
