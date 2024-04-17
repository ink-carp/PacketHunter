<script lang="ts">
  import { invoke } from '@tauri-apps/api/tauri';
  import { onDestroy } from 'svelte';
  import { bpf_statement ,bpf_isvalid } from '$lib/global';

  // 定义 debounce 计时器
  let debounceTimer: ReturnType<typeof setTimeout>;
  // 模拟 bpf_analyzer 函数
  function bpf_analyzer(input: string) {
    invoke('bpf_analyzer', { code: input }).then(res => {
        bpf_isvalid.set(true);
        console.debug('bpf_analyzer executed with input:', input,"  Result: Ok");
    }).catch(err => {
        bpf_isvalid.set(false);
        console.debug('bpf_analyzer executed with input:', input,"  Result:",err);
    });
  }
  const unsubscribe = bpf_statement.subscribe((value) => {
      // 当输入框值变化时，重置 debounce 计时器
      if (debounceTimer) clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
          bpf_analyzer(value);
      }, 500);
  });

  // 当输入框值变化时执行 bpf_analyzer 函数
  function handleInputChange(event: Event) {
      const inputElement = event.target as HTMLInputElement;
      bpf_statement.set(inputElement.value);
  }

  // 销毁时取消订阅和清除 debounce 计时器
  onDestroy(() => {
      if (debounceTimer) clearTimeout(debounceTimer);
      unsubscribe();
      console.debug("Bpf Destroyed!");
  });
</script>

<input type="text" bind:value={$bpf_statement} on:input={handleInputChange} style="background-color: {$bpf_isvalid ? 'lightgreen' : 'pink'}" placeholder="输入 BPF 语句" />

<style>
  input {
      width: 100%;
      height: 100%;
      font-size: 16px;
      border: 2px solid;
      border-radius: 5px;
  }
</style>
