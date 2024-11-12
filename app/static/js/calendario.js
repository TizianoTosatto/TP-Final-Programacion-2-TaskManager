const calendar = document.getElementById('calendar');
const daysContainer = document.getElementById('days');
const monthYear = document.getElementById('month-year');
const eventModal = document.getElementById('event-modal');
const eventNameInput = document.getElementById('event-name');
const addEventButton = document.getElementById('add-event');
const closeModalButton = document.getElementById('close-modal');
const prevMonthButton = document.getElementById('prev-month');
const nextMonthButton = document.getElementById('next-month');
const selectedDateElement = document.getElementById('selected-date');
const eventList = document.getElementById('event-list');

let prevMonthDOM= document.getElementById('prev-month');
let nextMonthDOM= document.getElementById('next-month');

let currentDate = new Date();
let events = {}; // Objeto para almacenar eventos varios por día

// Función para generar el calendario del mes actual
function generateCalendar() {
    const month = currentDate.getMonth();
    const year = currentDate.getFullYear();

    monthYear.textContent = `${getMonthName(month)} ${year}`;

    // Limpiar días del calendario
    daysContainer.innerHTML = '';

    // Obtener el primer día del mes y cuántos días tiene el mes
    const firstDay = new Date(year, month, 1);
    const lastDay = new Date(year, month + 1, 0);
    const totalDays = lastDay.getDate();
    const firstDayOfWeek = firstDay.getDay(); // Día de la semana del primer día del mes

    // Obtener el día actual
    const today = new Date();
    const todayDay = today.getDate();
    const todayMonth = today.getMonth();
    const todayYear = today.getFullYear();

    // Agregar celdas vacías antes del primer día del mes
    for (let i = 0; i < firstDayOfWeek; i++) {
        const emptyCell = document.createElement('div');
        daysContainer.appendChild(emptyCell);
    }

    // Agregar días del mes
    for (let day = 1; day <= totalDays; day++) {
        const dayCell = document.createElement('div');
        dayCell.classList.add('day');
        dayCell.textContent = day;

        // Marcar si hay eventos en este día
        if (events[`${year}-${month + 1}-${day}`]) {
            dayCell.style.backgroundColor = 'rgb(73, 131, 255)';
            dayCell.style.color ='white'; 

            dayCell.addEventListener('mouseover', function() {
                dayCell.style.backgroundColor = ' #b1a5f7'; // hover
            });
        
            dayCell.addEventListener('mouseout', function() {
                dayCell.style.backgroundColor = 'rgb(73, 131, 255)'; // Vuelve al color original
            });
        }

        // Resaltar el día actual
        if (day === todayDay && month === todayMonth && year === todayYear) {
            dayCell.classList.add('today'); 

        }

        // Agregar el evento de clic para mostrar el modal
        dayCell.addEventListener('click', () => openEventModal(year, month, day));

        daysContainer.appendChild(dayCell);
    }
}

// Función para abrir el modal de eventos
function openEventModal(year, month, day) {
    const dateString = `${year}-${month + 1}-${day}`;
    selectedDateElement.textContent = `${day} de ${getMonthName(month)} ${year}`;
    eventNameInput.value = ''; // Limpiar campo de evento
    eventList.innerHTML = ''; // Limpiar lista de eventos

    // Mostrar los eventos existentes de este día
    if (events[dateString]) {
        events[dateString].forEach((event, index) => {
            const eventItem = document.createElement('li');
            eventItem.textContent = event.descripcion;

            eventItem.style.background='#e7e7e7';
            eventItem.style.padding='5px';
            eventItem.style.borderRadius='5px';
            eventItem.style.listStyleType = 'none';
            
            // Botón para eliminar evento
            const deleteButton = document.createElement('button');
            deleteButton.textContent = 'Eliminar';
            deleteButton.style.borderRadius='10px';
            deleteButton.style.background='rgb(206, 17, 17)';
            deleteButton.addEventListener('click', () => deleteEvent(dateString, index));
            
            // Botón para editar evento
            const editButton = document.createElement('button');
            editButton.textContent = 'Editar';
            editButton.style.borderRadius='10px';
            editButton.style.background= 'rgb(74, 168, 223)';
            editButton.addEventListener('click', () => editEvent(dateString, index));
            
            eventItem.appendChild(editButton);
            eventItem.appendChild(deleteButton);
            eventList.appendChild(eventItem);
        });
    }

    eventModal.classList.remove('hidden');
    addEventButton.onclick = () => addEvent(dateString);
    closeModalButton.onclick = () => eventModal.classList.add('hidden');
}

// Función para agregar un evento
function addEvent(dateString) {
    const eventName = eventNameInput.value.trim();
    if (eventName !== '') {
        if (!events[dateString]) {
            events[dateString] = [];
        }
        events[dateString].push(eventName);
        generateCalendar(); // Regenerar calendario
        eventModal.classList.add('hidden');
    }
}

// Función para eliminar un evento
function deleteEvent(dateString, index) {
    events[dateString].splice(index, 1);
    if (events[dateString].length === 0) {
        delete events[dateString]; // Eliminar el día si no tiene eventos
    }
    generateCalendar();
    openEventModal(new Date(dateString).getFullYear(), new Date(dateString).getMonth(), new Date(dateString).getDate());
}


// Función para editar un evento
function editEvent(dateString, index) {
    const newEventName = prompt("Editar evento:", events[dateString][index]);
    if (newEventName) {
        // events[dateString][index] = newEventName;
        const eventId = events[dateString][index].id;
        fetch(`/editar_evento/${eventId}`, {
            method: 'PUT', // o 'PATCH' dependiendo de tu elección
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ descripcion: newEventName })
        })
        .then(response => response.json())
        .then(data => {
            // Actualiza el evento localmente
            events[dateString][index].descripcion = newEventName;
            generateCalendar();  // Regenerar el calendario para reflejar el cambio
            openEventModal(new Date(dateString).getFullYear(), new Date(dateString).getMonth(), new Date(dateString).getDate());
        })
        .catch(error => console.error('Error al editar el evento:', error));
    }
}

document.addEventListener('DOMContentLoaded', obtenerTareas);

function loadEvents() {
    fetch('/obtener_eventos', {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json'
        
        }
    })
    .then(response => response.json())
    .then(data => {
        data.forEach(evento => {
            if (!events[evento.fecha]) {
                events[evento.fecha] = [];
            }
            events[evento.fecha].push({ id: evento.id, descripcion: evento.descripcion });
        });
        generateCalendar();
    })
    .catch(error => console.error('Error al cargar eventos:', error));
    
}
loadEvents();

function addEvent(dateString) {
    const eventName = eventNameInput.value.trim();
    if (eventName !== '') {
        if (!events[dateString]) {
            events[dateString] = [];
        }
        //  events[dateString].push(eventName);
        
        // Guarda el evento en la base de datos
        fetch('/agregar_evento', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ descripcion: eventName, fecha: dateString })
        })
        .then(response => response.json())
        .then(data => {
            events[dateString].push({ id: data.id, descripcion: data.descripcion });
            generateCalendar(); // Regenerar el calendario para reflejar el nuevo evento
            eventModal.classList.add('hidden');
        })
        .catch(error => console.error('Error al agregar evento:', error));
    }
}
function deleteEvent(dateString, index) {
    const eventId = events[dateString][index].id;
    events[dateString].splice(index, 1);
    if (events[dateString].length === 0) {
        delete events[dateString]; // Eliminar el día si no tiene eventos
    }

    // Eliminar el evento de la base de datos
    fetch(`/eliminar_evento/${eventId}`, {
        method: 'DELETE'
    })
    .then(response => response.json())
    .then(data => {
        generateCalendar();
        openEventModal(new Date(dateString).getFullYear(), new Date(dateString).getMonth(), new Date(dateString).getDate());
    })
    .catch(error => console.error('Error al eliminar evento:', error));
}
//------------------------------------------------------------------------------------------------------------------
// Funciones para cambiar de mes
prevMonthButton.addEventListener('click', () => {
    currentDate.setMonth(currentDate.getMonth() - 1);
    generateCalendar();
});

nextMonthButton.addEventListener('click', () => {
    currentDate.setMonth(currentDate.getMonth() + 1);
    generateCalendar();
});

// Función para obtener el nombre del mes
function getMonthName(month) {
    const months = ['Enero', 'Febrero', 'Marzo', 'Abril', 'Mayo', 'Junio', 'Julio', 'Agosto', 'Septiembre', 'Octubre', 'Noviembre', 'Diciembre'];
    return months[month];
}

// Inicializar calendario
generateCalendar();