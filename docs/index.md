---
layout: home
title: Welcome
permalink: /
has_children: true
nav_order: 0
has_toc: false
---

<div style="display:flex;align-items: center">
   <button class="btn js-toggle-dark-mode">Switch to Light Mode</button> 
</div>


<h1>Developer Learning Guide </h1>
<script>
const toggleDarkMode = document.querySelector('.js-toggle-dark-mode');

jtd.addEvent(toggleDarkMode, 'click', function(){
  if (jtd.getTheme() === 'dark') {
    jtd.setTheme('light');
    toggleDarkMode.textContent = 'Return to The Dark Side';
  } else {
    jtd.setTheme('dark');
    toggleDarkMode.textContent = 'Switch to Light Mode';
  }
});
</script>

To be updated


- Light Mode to be tailored
- Change code block style-harder to read

## Contribute

Any descriptions unclear?
We welcome you to contribute to our guide:
<br/> 

[Contrast GitHub Community](https://github.com/sara-kathryn/DeveloperLearnGuide){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }


## Nav Testing area

{: .d-inline-block }

New
{: .label .label-green }


#### Example
{: .no_toc }

```yaml
# Color scheme supports "light" (default) and "dark"
color_scheme: dark
```
