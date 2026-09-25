import './style.css'
import './reportFilters.css'
import './reportSorting.css'
import { mount } from 'svelte'
import App from './App.svelte'
import { setupDefaultReportVisibility } from './reportVisibility'
import { setupReportSorting } from './reportSorting'

const target = document.getElementById('app')
if (!target) {
  throw new Error('App mount target was not found')
}

const app = mount(App, { target })
setupDefaultReportVisibility(target)
setupReportSorting(target)

export default app
