import 'codemirror/lib/codemirror.css';
import 'tui-editor/dist/tui-editor.css';
import 'tui-editor/dist/tui-editor-contents.css';
import 'highlight.js/styles/github.css';


import Editor from 'tui-editor';


const instance = new Editor({
  el: document.querySelector('#markdown_editor'),
  initialEditType: 'markdown',
  previewStyle: 'vertical',
  height: '300px'
});

instance.getHtml();