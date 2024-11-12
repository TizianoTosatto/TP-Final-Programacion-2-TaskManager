// Info date
const dateNumber = document.getElementById('dateNumber');
const dateText = document.getElementById('dateText');
const dateMonth = document.getElementById('dateMonth');
const dateYear = document.getElementById('dateYear');

// Tasks Container
const tasksContainer = document.getElementById('tasksContainer');

const setDate = () => {
    const date = new Date();
    dateNumber.textContent = date.toLocaleString('es', { day: 'numeric' });
    dateText.textContent = date.toLocaleString('es', { weekday: 'long' });
    dateMonth.textContent = date.toLocaleString('es', { month: 'short' });
    dateYear.textContent = date.toLocaleString('es', { year: 'numeric' });
};

const addNewTask = event => {
    event.preventDefault();
    const { value } = event.target.taskText;
    if(!value) return;

    const task = document.createElement('div');
    task.classList.add('task', 'roundBorder');

    task.addEventListener('click', changeTaskState)
    task.textContent = value;
    tasksContainer.prepend(task);
    event.target.reset();
};

document.addEventListener('DOMContentLoaded', obtenerTareas); // Obtener tareas al cargar la página

const taskForm = document.getElementById('taskForm');
const taskInput = document.getElementById('taskInput');
const taskList = document.getElementById('taskList');

// Función para agregar una nueva tarea
taskForm.addEventListener('submit', async function(event) {
    event.preventDefault();

    const descripcion = taskInput.value.trim();
    if (descripcion === '') return;

    // Hacer una solicitud para agregar la tarea
    const response = await fetch('/agregar_tarea', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ descripcion })
    });

    const tarea = await response.json();
    agregarTareaDOM(tarea.id, tarea.descripcion);
    taskInput.value = ''; // Limpiar el campo de entrada
});

// Función para obtener todas las tareas del usuario
async function obtenerTareas() {
    const response = await fetch('/obtener_tareas');
    const tareas = await response.json();

    taskList.innerHTML = ''; // Limpiar la lista antes de renderizar
    tareas.forEach(tarea => agregarTareaDOM(tarea.id, tarea.descripcion));
}

// Función para agregar tarea en el DOM
function agregarTareaDOM(id, descripcion) {
    const li = document.createElement('li');
    li.textContent = descripcion;

    const deleteButton = document.createElement('button');
    deleteButton.textContent = 'Eliminar';
    deleteButton.style.color = 'white';
    deleteButton.style.marginLeft= '20px'
    deleteButton.style. justifycontent='flex-end';
    deleteButton.style.background='var(--secondary)';
    deleteButton.style.padding='5px';
    deleteButton.style.borderRadius='5px';
    
    
    deleteButton.onclick = () => eliminarTarea(id, li);

    li.appendChild(deleteButton);
    taskList.appendChild(li);
}

// Función para eliminar una tarea
async function eliminarTarea(id, li) {
    await fetch(`/eliminar_tarea/${id}`, { method: 'DELETE' });
    taskList.removeChild(li); // Eliminar la tarea del DOM
}

setDate();