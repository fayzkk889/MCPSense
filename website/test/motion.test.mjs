import test from 'node:test';
import assert from 'node:assert/strict';
import { setupInspectionMotion } from '../src/motion.js';

function environment(reduce = false) {
  const previous = { window: globalThis.window, raf: globalThis.requestAnimationFrame, observer: globalThis.IntersectionObserver };
  const frames = [], classes = new Set(), events = new Map();
  const button = () => ({ hidden:true, textContent:'', listeners:new Map(), addEventListener(name,fn){this.listeners.set(name,fn);}, click(){this.listeners.get('click')();} });
  const replay = button(), pause = button();
  const preference = {matches:reduce, addEventListener(name,fn){this.listener=fn;}, change(value){this.matches=value;this.listener();}};
  const state = {observed:false,disconnected:false};
  const Observer = class {
    constructor(callback){state.intersect=callback;}
    observe(){state.observed=true;}
    disconnect(){state.disconnected=true;}
  };
  globalThis.window = {matchMedia:()=>preference,IntersectionObserver:Observer};
  globalThis.IntersectionObserver = Observer;
  globalThis.requestAnimationFrame = callback => frames.push(callback);
  const engine = {
    classList:{remove(...names){names.forEach(name=>classes.delete(name));},add(name){classes.add(name);},toggle(name){if(classes.has(name)){classes.delete(name);return false;}classes.add(name);return true;}},
    querySelector(selector){return selector==='[data-replay]'?replay:pause;},
    addEventListener(name,fn){events.set(name,fn);},
  };
  return {engine,classes,replay,pause,preference,state,
    enter(){state.intersect([{isIntersecting:true}]);},
    frames(){while(frames.length)frames.shift()();},
    end(name){events.get('animationend')({animationName:name});},
    restore(){for(const [key,value] of [['window',previous.window],['requestAnimationFrame',previous.raf],['IntersectionObserver',previous.observer]]){if(value===undefined)delete globalThis[key];else globalThis[key]=value;}},
  };
}

test('reduced-motion users get a static illustration, including during preference changes', () => {
  const ui=environment(true);
  try {
    setupInspectionMotion(ui.engine);
    assert.equal(ui.state.observed,false);
    assert.equal(ui.replay.hidden,true);
    assert.equal(ui.pause.hidden,true);
    assert.equal(ui.classes.has('is-running'),false);
    ui.preference.change(false);
    assert.equal(ui.replay.hidden,false);
    assert.equal(ui.classes.has('is-running'),false);
    ui.replay.click(); ui.frames();
    assert.equal(ui.classes.has('is-running'),true);
    ui.preference.change(true);
    assert.equal(ui.classes.has('is-running'),false);
    assert.equal(ui.replay.hidden,true);
    assert.equal(ui.pause.hidden,true);
  } finally {ui.restore();}
});

test('the visible trace can pause, resume and return to a static result after one sweep', () => {
  const ui=environment();
  try {
    setupInspectionMotion(ui.engine);
    assert.equal(ui.classes.has('is-running'),false);
    ui.enter(); ui.frames();
    assert.equal(ui.classes.has('is-running'),true);
    assert.equal(ui.state.disconnected,true);
    ui.pause.click();
    assert.equal(ui.classes.has('is-paused'),true);
    assert.equal(ui.pause.textContent,'Resume animation');
    ui.pause.click();
    assert.equal(ui.classes.has('is-paused'),false);
    assert.equal(ui.pause.textContent,'Pause animation');
    ui.end('unrelated-hover-effect');
    assert.equal(ui.classes.has('is-running'),true);
    ui.end('inspection-sweep');
    assert.equal(ui.classes.has('is-running'),false);
    assert.equal(ui.pause.hidden,true);
  } finally {ui.restore();}
});

test('replay resets a paused trace, and a late reduced-motion change cancels a queued start', () => {
  const ui=environment();
  try {
    setupInspectionMotion(ui.engine);
    ui.enter(); ui.frames(); ui.pause.click();
    ui.replay.click(); ui.frames();
    assert.equal(ui.classes.has('is-running'),true);
    assert.equal(ui.classes.has('is-paused'),false);
    ui.replay.click();
    ui.preference.change(true); ui.frames();
    assert.equal(ui.classes.has('is-running'),false);
    assert.equal(ui.pause.hidden,true);
  } finally {ui.restore();}
});
