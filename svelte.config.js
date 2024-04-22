import adapter from '@sveltejs/adapter-static' // 这将会通过 adapter-auto 更改
import preprocess from 'svelte-preprocess'

/** @type {import('@sveltejs/kit').Config} */
const config = {
  // 查询 https://github.com/sveltejs/svelte-preprocess
  // 以了解更多关于预处理器的信息
  preprocess: preprocess(),

  kit: {
    adapter: adapter(),
  },
}

export default config