const symfony = require("./symfony");
const wordpress = require("./wordpress");
const drupal = require("./drupal");
const laravel = require("./laravel");
const joomla = require("./joomla");
const prestashop = require("./prestashop");
const typo3 = require("./typo3");
const magento = require("./magento");
const { assertPluginShape } = require("./plugin.interface");

const PLUGINS = [symfony, wordpress, drupal, laravel, joomla, prestashop, typo3, magento];
for (const plugin of PLUGINS) assertPluginShape(plugin);

function allApplicationPlugins() { return PLUGINS.slice(); }
function getApplicationPlugin(id) { return PLUGINS.find(p => p.id === id) || null; }

module.exports = { allApplicationPlugins, getApplicationPlugin };
